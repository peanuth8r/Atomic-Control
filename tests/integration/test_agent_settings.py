import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.app.main import create_app
from apps.api.app.models import Audit, Enrollment
from apps.api.app.services.common import digest
from tests.integration.test_agent_packages import generate, register, unpack
from tests.integration.test_agent_packages import real as real

ADMIN = {"X-Test-User": "admin"}
PATH = "/api/v1/admin/agent-settings"


def save(client, minutes, headers=ADMIN):
    return client.put(PATH, headers=headers, json={"enrollment_token_minutes": minutes})


def test_default_and_durable_update(env):
    client = env["client"]
    assert client.get(PATH, headers=ADMIN).json() == {"enrollment_token_minutes": 60}
    old = client.post("/api/v1/enrollment-tokens", headers=ADMIN, json={"hostname": "BEFORE"}).json()
    with env["app"].state.sessions() as db:
        expiry = db.scalar(select(Enrollment).where(Enrollment.digest == digest(old["token"]))).expires_at
    assert old["expires_in"] == 3600
    assert save(client, 120).status_code == 200
    restarted = create_app(env["settings"])
    restarted.dependency_overrides.update(env["app"].dependency_overrides)
    assert TestClient(restarted).get(PATH, headers=ADMIN).json()["enrollment_token_minutes"] == 120
    fresh = client.post("/api/v1/enrollment-tokens", headers=ADMIN, json={"hostname": "AFTER"}).json()
    assert fresh["expires_in"] == 7200
    assert (
        client.get("/api/v1/agents/package-options", headers=ADMIN).json()["token_lifetime_seconds"] == 7200
    )
    with env["app"].state.sessions() as db:
        assert (
            db.scalar(select(Enrollment).where(Enrollment.digest == digest(old["token"]))).expires_at
            == expiry
        )
        assert (
            7190
            < db.scalar(select(Enrollment).where(Enrollment.digest == digest(fresh["token"]))).expires_at
            - time.time()
            <= 7200
        )
        assert db.scalar(select(Audit).where(Audit.action == "agent.settings-updated"))


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_administrator_only(env, role):
    headers = {"X-Test-User": role}
    assert env["client"].get(PATH, headers=headers).status_code == 403
    assert save(env["client"], 120, headers).status_code == 403


@pytest.mark.parametrize("value", [0, 4, 1441, -1, 60.5, "60", True, None])
def test_reject_invalid_lifetimes(env, value):
    assert save(env["client"], value).status_code == 422
    assert env["client"].get(PATH, headers=ADMIN).json()["enrollment_token_minutes"] == 60


@pytest.mark.parametrize("minutes", [5, 60, 1440])
def test_package_uses_issuance_setting(real, minutes):
    import json

    client = real["client"]
    assert save(client, minutes).status_code == 200
    actor = register(client)
    response = generate(real, actor=actor["id"], enrollment=True)
    files = unpack(response)
    bootstrap = json.loads(files["bootstrap.json"])
    assert bootstrap["token_lifetime_seconds"] == minutes * 60
    assert minutes * 60 - 10 < bootstrap["expires_at"] - time.time() <= minutes * 60
    assert f"{minutes} minutes after generation".encode() in files["README.txt"]
    assert save(client, 90).status_code == 200
    with real["app"].state.sessions() as db:
        stored = db.scalar(
            select(Enrollment).where(Enrollment.digest == digest(bootstrap["enrollment_token"]))
        )
        assert stored.expires_at == bootstrap["expires_at"]
    payload = {
        "token": bootstrap["enrollment_token"],
        "hostname": actor["hostname"],
        "agent_version": "0.2.0",
        "os_version": "Windows",
    }
    assert client.post("/api/v1/agents/enroll", json=payload).status_code == 200
    assert client.post("/api/v1/agents/enroll", json=payload).status_code != 200


def test_expired_tokens_stay_expired_after_increasing_setting(env):
    client = env["client"]
    token = client.post("/api/v1/enrollment-tokens", headers=ADMIN, json={"hostname": "EXPIRED"}).json()[
        "token"
    ]
    with env["app"].state.sessions() as db, db.begin():
        db.scalar(select(Enrollment).where(Enrollment.digest == digest(token))).expires_at = time.time() - 1
    assert save(client, 1440).status_code == 200
    response = client.post(
        "/api/v1/agents/enroll",
        json={"token": token, "hostname": "EXPIRED", "agent_version": "0.2.0", "os_version": "Windows"},
    )
    assert response.status_code != 200
