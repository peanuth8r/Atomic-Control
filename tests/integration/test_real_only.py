import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from apps.agent.job_client import JobClient
from apps.api.app.config import Settings
from apps.api.app.models import Actor, AtomicTest
from tests.support.fixtures import fixture_result


@pytest.mark.parametrize(
    "settings",
    [
        {"mode": "mock"},
        {"mode": "demo"},
        {"dev_auth": True},
        {"dev_auth": "true"},
        {"oidc_issuer": ""},
        {"signing_key_file": ""},
    ],
)
def test_real_execution_configuration_rejects_removed_modes_and_missing_authority(settings):
    with pytest.raises(ValidationError):
        Settings(**settings)


def test_agent_transport_has_no_http_opt_in():
    with pytest.raises(ValueError, match="HTTPS"):
        JobClient("http://127.0.0.1:8000", "test-credential")


def test_legacy_actor_is_hidden_and_cannot_authenticate_or_dispatch(env):
    with env["app"].state.sessions() as db, db.begin():
        db.get(Actor, env["actor"]).simulated = True
    assert env["client"].get("/api/v1/actors").json()["items"] == []
    response = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={})
    assert response.status_code == 403


def test_legacy_definition_is_hidden_and_cannot_receive_approval(env):
    guid = "11111111-1111-4111-8111-111111111111"
    with env["app"].state.sessions() as db, db.begin():
        db.get(AtomicTest, guid).simulated = True
    assert env["client"].get("/api/v1/tests?approved_only=true").json()["items"] == []
    test = env["client"].get("/api/v1/tests/" + guid).json()
    assert not test["approved"] and not test["execution_ready"]
    response = env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers={"X-Test-User": "admin"},
        json={
            "content_sha256": test["content_sha256"],
            "source_revision": test["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    )
    assert response.status_code == 409


def test_every_dispatched_job_is_signed_and_fabricated_mode_cannot_complete_it(env, approved_job):
    job = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={}).json()["job"]
    key = serialization.load_pem_private_key(
        __import__("pathlib").Path(env["settings"].signing_key_file).read_bytes(), password=None
    )
    claims = jwt.decode(
        job["grant"], key.public_key(), algorithms=["RS256"], issuer="atomic-control", audience=env["actor"]
    )
    assert claims["snapshot_hash"] == job["snapshot_hash"]
    body = fixture_result(job)
    body["simulated"] = True
    response = env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=env["agent"], json=body
    )
    assert response.status_code == 409
    assert env["client"].get(f"/api/v1/runs/{job['run_id']}").json()["status"] == "claimed"


def test_configuration_package_requires_a_real_verification_key(env):
    env["settings"].signing_key_file = ""
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/agent-package",
        headers={"X-Test-User": "admin"},
        json={"api_url": "https://control.example.test", "include_enrollment": False},
    )
    assert response.status_code == 503 and response.json()["error"]["code"] == "signing_key_unavailable"


def test_startup_refuses_an_entire_historical_fixture_database(env):
    from fastapi.testclient import TestClient

    with env["app"].state.sessions() as db, db.begin():
        db.get(Actor, env["actor"]).simulated = True
    with pytest.raises(RuntimeError, match="Historical fixture databases"):
        with TestClient(env["app"]):
            pass
