"""Safe Windows-service diagnostics; no service, credentials or Atomic commands run."""

import json
import sys
import time
from types import SimpleNamespace

import httpx
import pytest

from apps.agent import artifact_execution, execution_broker, logging, service


@pytest.mark.parametrize("name,level", [("worker.error", "error"), ("job.claimed", "info")])
def test_windows_events_reach_application_log_when_console_is_unavailable(monkeypatch, name, level):
    messages = []
    monkeypatch.setattr(logging, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setitem(
        sys.modules,
        "servicemanager",
        SimpleNamespace(
            LogErrorMsg=lambda value: messages.append(("error", value)),
            LogInfoMsg=lambda value: messages.append(("info", value)),
        ),
    )

    def broken_console(*args, **kwargs):
        raise OSError("Service has no console")

    monkeypatch.setattr(logging, "print", broken_console, raising=False)
    logging.event(name, stage="claim_job")
    assert messages[0][0] == level
    value = json.loads(messages[0][1])
    assert value["event"] == name and value["stage"] == "claim_job"


def test_event_log_failure_does_not_change_execution_behavior(monkeypatch, capsys):
    def unavailable(value):
        raise OSError("Event Log unavailable")

    monkeypatch.setattr(logging, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setitem(sys.modules, "servicemanager", SimpleNamespace(LogErrorMsg=unavailable))
    logging.event("worker.error", stage="execute_job")
    assert json.loads(capsys.readouterr().out)["stage"] == "execute_job"


def test_error_fields_exclude_messages_requests_and_headers():
    response = httpx.Response(
        403, request=httpx.Request("GET", "https://example.test", headers={"Authorization": "secret-token"})
    )
    error = httpx.HTTPStatusError("credential=secret-token", request=response.request, response=response)
    assert logging.error_fields(error) == {"error_type": "HTTPStatusError", "http_status": 403}
    assert logging.error_fields(ValueError("authorization=secret-token")) == {"error_type": "ValueError"}
    assert (
        logging.error_fields(ValueError("Unknown or mismatched provisioned execution identity"))["reason"]
        == "profile_binding_mismatch"
    )


@pytest.mark.parametrize("phase", ["verify_assignment", "write_preparation_journal"])
def test_preparation_failure_is_logged_before_a_journal_exists(tmp_path, monkeypatch, phase):
    events = []
    broker = SimpleNamespace(config={}, public_key="public-key", journal=tmp_path / "active.json")

    def denied(*args, **kwargs):
        raise PermissionError(13, "credential=secret-token")

    monkeypatch.setattr(artifact_execution, "event", lambda name, **fields: events.append((name, fields)))
    monkeypatch.setattr(
        execution_broker, "verify_job", denied if phase == "verify_assignment" else lambda *args, **kwargs: {}
    )
    monkeypatch.setattr(artifact_execution, "persist", denied)
    with pytest.raises(PermissionError):
        artifact_execution.execute(
            broker, {"grant": "secret-token"}, lambda job: pytest.fail("No execution after preflight failure")
        )
    assert events == [
        ("job.preparation_error", {"stage": phase, "error_type": "PermissionError", "errno": 13})
    ]
    assert not broker.journal.exists()
    assert "secret-token" not in json.dumps(events)


@pytest.mark.parametrize("phase", ["claim_job", "execute_job"])
def test_worker_records_claim_transport_and_preflight_failures_without_secrets(tmp_path, monkeypatch, phase):
    config_file = tmp_path / "agent.json"
    config = {
        "actor_id": "fixture-actor",
        "api_url": "https://example.test",
        "credential_file": "not-read",
        "os": "windows",
    }
    config_file.write_text(json.dumps(config))
    stop = SimpleNamespace(stopped=False)
    stop.is_set = lambda: stop.stopped
    stop.wait = lambda seconds: setattr(stop, "stopped", True)
    events = []

    class Client:
        def __init__(self, *args):
            pass

        def post(self, path, *args):
            if path.endswith("claim"):
                if phase == "claim_job":
                    raise httpx.ReadTimeout("credential=secret-token")
                return {"job": {"run_id": "fixture-run"}}
            return {}

        def close(self):
            pass

    class Broker:
        def __init__(self, *args):
            self.journal = tmp_path / "active.json"

        def recover(self):
            pass

        def execute(self, job):
            raise ValueError("Unknown or mismatched provisioned execution identity")

    monkeypatch.setattr(
        service,
        "load_credential",
        lambda path: {
            "actor_id": "fixture-actor",
            "expires_at": time.time() + 7200,
            "credential": "secret-token",
        },
    )
    monkeypatch.setattr(service, "JobClient", Client)
    monkeypatch.setattr(service, "Broker", Broker)
    monkeypatch.setattr(service, "heartbeat_payload", lambda config: {})
    monkeypatch.setattr(service, "event", lambda name, **fields: events.append((name, fields)))
    service.worker(config_file, stop)
    failures = [value for name, value in events if name == "worker.error"]
    assert failures[0]["stage"] == phase
    assert "secret-token" not in json.dumps(events)
