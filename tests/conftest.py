# ruff: noqa: E402

import pytest
import yaml
from fastapi import Request

from tests.support.bootstrap import configure_environment

configure_environment()
from fastapi.testclient import TestClient

from apps.api.app.auth import Principal, human
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import Base
from tests.support.fixtures import seed


@pytest.fixture
def env(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/test.db",
        approval_mode="per_run",
        public_url="https://control.example.test",
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    actor, token = seed(settings)

    def test_identity(request: Request):
        if request.headers.get("authorization"):
            return human(request)
        name = request.headers.get("x-test-user", request.cookies.get("atomic_test_user", "viewer"))
        roles = {
            "viewer": {"viewer"},
            "operator": {"viewer", "operator"},
            "approver": {"viewer", "approver", "privileged_approver"},
            "admin": {"viewer", "operator", "approver", "privileged_approver", "administrator"},
        }
        request.state.identity = "dev:" + name
        return Principal(request.state.identity, frozenset(roles.get(name, set())), frozenset())

    app.dependency_overrides[human] = test_identity
    client = TestClient(app)
    profiles = client.get(f"/api/v1/actors/{actor}/profiles").json()
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        yaml.safe_dump(
            {
                "subjects": {
                    name: [
                        {
                            "actions": ["execute", "check", "cleanup", "approve"],
                            "actors": [actor],
                            "profiles": [p["id"] for p in profiles],
                            "tests": ["11111111-1111-4111-8111-111111111111"],
                            "risks": ["low", "medium", "high"],
                        }
                    ]
                    for name in [
                        "dev:operator",
                        "dev:admin",
                        "dev:approver",
                        "mcp:operator",
                        "human:approver",
                    ]
                }
            }
        )
    )
    settings.policy_file = str(policy)
    return {
        "settings": settings,
        "app": app,
        "client": client,
        "actor": actor,
        "agent": {"Authorization": "Bearer " + token},
        "profiles": profiles,
    }


@pytest.fixture
def request_job(env):
    def make(profile="standard-user", key=None, user="operator", action="execute"):
        import uuid

        return env["client"].post(
            "/api/v1/runs",
            headers={"X-Test-User": user, "Idempotency-Key": key or str(uuid.uuid4())},
            json={
                "atomic_guid": "11111111-1111-4111-8111-111111111111",
                "actor_id": env["actor"],
                "execution_profile_id": next(p["id"] for p in env["profiles"] if p["profile_key"] == profile),
                "reason": "Validate authorized lab telemetry",
                "action": action,
            },
        )

    return make


@pytest.fixture
def approved_job(env, request_job):
    run = request_job().json()
    response = env["client"].post(
        f"/api/v1/runs/{run['run_id']}/approve",
        headers={"X-Test-User": "approver"},
        json={"reason": "Authorized isolated lab validation"},
    )
    assert response.status_code == 200, response.text
    return run
