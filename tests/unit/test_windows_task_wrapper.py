"""Windows wrapper failure evidence with processes and native APIs replaced."""

import hashlib
import json
import time

import pytest

from apps.agent import task_wrapper as wrapper


@pytest.fixture
def assignment(tmp_path, monkeypatch):
    profile_id = "11111111-1111-4111-8111-111111111111"
    folder = tmp_path / profile_id
    (folder / "output").mkdir(parents=True)
    module = tmp_path / "module.psd1"
    module.write_bytes(b"reviewed module fixture")
    powershell = tmp_path / "powershell.exe"
    powershell.write_bytes(b"not executed")
    key = tmp_path / "public.pem"
    key.write_text("not used by mocked signature verification")
    config = {
        "state_root": str(tmp_path),
        "public_key_file": str(key),
        "powershell_path": str(powershell),
        "invoke_module_path": str(module),
        "invoke_module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    job = {"attempt_id": profile_id, "snapshot": {"action": "execute", "timeout_seconds": 10}}
    (folder / "job.json").write_text(json.dumps(job))
    (folder / "lease.json").write_text(json.dumps({"attempt_id": profile_id, "expires_at": time.time() + 60}))
    profile = {"id": profile_id, "expected_sid": "S-1-5-21-1", "privilege": "standard"}
    identity = {
        "actual_account_sid": profile["expected_sid"],
        "elevated": False,
        "admin_member": False,
        "integrity_level": "medium",
    }
    monkeypatch.setattr(wrapper, "verify_job", lambda *_: profile)
    monkeypatch.setattr(wrapper, "capture_identity", lambda *_: identity)
    return config, config_file, folder, job, profile_id


@pytest.mark.parametrize(
    "stage",
    [
        "verify_signed_assignment",
        "verify_powershell_path",
        "verify_invoke_module_path",
        "verify_invoke_module_pin",
        "verify_invoke_module_hash",
        "join_process_containment",
        "open_process_containment",
        "assign_process_containment",
        "launch_powershell",
    ],
)
def test_wrapper_persists_actionable_failure_without_exposing_exception_messages(
    assignment, monkeypatch, stage
):
    config, config_file, folder, job, profile_id = assignment
    from apps.agent import windows_processes

    def failure(*args, **kwargs):
        raise PermissionError(13, "authorization=private-example-token")

    if stage == "verify_signed_assignment":
        monkeypatch.setattr(wrapper, "verify_job", failure)
    elif stage == "verify_powershell_path":
        config["powershell_path"] = str(config_file.parent / "missing.exe")
    elif stage == "verify_invoke_module_path":
        config["invoke_module_path"] = str(config_file.parent / "missing.psd1")
    elif stage == "verify_invoke_module_pin":
        config["invoke_module_sha256"] = "REPLACE_WITH_REVIEWED_MODULE_SHA256"
    elif stage == "verify_invoke_module_hash":
        config["invoke_module_sha256"] = "0" * 64
    elif stage == "join_process_containment":
        job["snapshot"]["artifact"] = {"fixture": True}
        (folder / "job.json").write_text(json.dumps(job))
        monkeypatch.setattr(windows_processes, "join", failure)
    elif stage in {"open_process_containment", "assign_process_containment"}:
        job["snapshot"]["artifact"] = {"fixture": True}
        (folder / "job.json").write_text(json.dumps(job))

        def denied(*args):
            error = PermissionError(13, "authorization=private-example-token")
            error.winerror = 5
            raise windows_processes.JoinError(stage, error)

        monkeypatch.setattr(windows_processes, "join", denied)
    config_file.write_text(json.dumps(config))
    launches = []

    def start(*args, **kwargs):
        launches.append(args)
        if stage != "launch_powershell":
            pytest.fail("No process may launch after preflight failure")
        failure()

    monkeypatch.setattr(wrapper.subprocess, "Popen", start)
    with pytest.raises((OSError, ValueError)):
        wrapper.run(config_file, profile_id)
    result = json.loads((folder / "output" / "result.json").read_text())
    assert f"stage={stage}" in result["stderr"]
    assert "private-example-token" not in result["stderr"]
    assert "authorization=" not in result["stderr"]
    if stage in {"verify_signed_assignment", "join_process_containment", "launch_powershell"}:
        assert "errno=13" in result["stderr"]
    if stage in {"open_process_containment", "assign_process_containment"}:
        assert "winerror=5" in result["stderr"]
    assert result["status"] == ("inconclusive" if stage == "launch_powershell" else "failed")
    assert len(launches) == int(stage == "launch_powershell")
    assert result["exit_code"] is None
    assert result["started_at"] <= result["finished_at"]
    if stage == "verify_signed_assignment":
        assert result["identity"] is None
    else:
        assert result["identity"]["verified"]


def test_completed_wrapper_retains_successful_result(assignment, monkeypatch):
    _, config_file, folder, _, profile_id = assignment

    class Process:
        returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            return self.returncode

    monkeypatch.setattr(wrapper.subprocess, "Popen", lambda *args, **kwargs: Process())
    wrapper.run(config_file, profile_id)
    result = json.loads((folder / "output" / "result.json").read_text())
    assert result["status"] == "succeeded" and result["exit_code"] == 0
    assert result["identity"]["verified"] and result["stderr"] == ""
