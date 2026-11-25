from uuid import uuid4

import pytest
import yaml
from fastapi import Request
from sqlalchemy import func, select

from apps.api.app.auth import Principal, human
from apps.api.app.auth.policy import authorize_execution
from apps.api.app.models import Actor, AtomicTest, Audit, Profile, Revision, Run
from apps.api.app.models import TestApproval as CatalogApproval


@pytest.fixture
def access(env, tmp_path):
    path = tmp_path / "authorization.yaml"
    path.write_text("subjects: {}\n")
    path.chmod(0o600)
    settings = env["settings"]
    settings.mode = "real"
    settings.dev_auth = False
    settings.policy_file = str(path)

    def identity(request: Request):
        return Principal(
            request.headers.get("x-human", "admin-one"),
            frozenset(request.headers.get("x-roles", "viewer,administrator").split(",")),
            frozenset(),
            request.headers.get("x-mcp") == "true",
        )

    env["app"].dependency_overrides[human] = identity
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.simulated = False
        revision = "a" * 40
        db.add(Revision(id=revision))
        db.flush()
        test = db.get(AtomicTest, "11111111-1111-4111-8111-111111111111")
        test.simulated = False
        test.revision = revision
        db.get(CatalogApproval, test.guid).revision = revision
    profile = next(item for item in env["profiles"] if item["profile_key"] == "standard-user")
    return {
        **env,
        "path": path,
        "profile": profile,
        "payload": {
            "operation": "grant",
            "subject": "requester-subject",
            "actor_id": env["actor"],
            "profile_id": profile["id"],
            "test_guid": "11111111-1111-4111-8111-111111111111",
            "actions": ["execute", "check"],
        },
    }


def prepare(access, **overrides):
    version = access["client"].get("/api/v1/execution-access").json()["version"]
    return access["client"].post(
        "/api/v1/execution-access/preview", json={**access["payload"], "version": version, **overrides}
    )


def apply(access, token, headers=None):
    return access["client"].post(
        "/api/v1/execution-access/apply",
        headers=headers or {},
        json={"preview_token": token, "confirmed": True, "reason": "Reviewed exact lab test scope"},
    )


def test_preview_is_read_only_and_confirmed_grants_are_scoped_audited_and_revocable(access):
    before = access["path"].read_bytes()
    preview = prepare(access)
    assert preview.status_code == 200, preview.text
    assert access["path"].read_bytes() == before
    value = preview.json()
    response = apply(access, value["preview_token"])
    assert response.status_code == 200, response.text
    assert access["path"].stat().st_mode & 0o777 == 0o600
    grant = response.json()["grants"][0]
    assert grant["actors"] == [access["actor"]] and grant["profiles"] == [access["profile"]["id"]]
    assert grant["risks"] == ["low"]
    with access["app"].state.sessions() as db:
        actor = db.get(Actor, access["actor"])
        profile = db.get(Profile, access["profile"]["id"])
        test = db.get(AtomicTest, access["payload"]["test_guid"])
        authorize_execution(
            access["settings"],
            Principal("requester-subject", frozenset({"operator"}), frozenset()),
            actor,
            profile,
            test,
            "low",
            "execute",
        )
        assert db.scalar(select(func.count()).select_from(Run)) == 0
        assert {"execution_access.intent", "execution_access.applied"} <= set(
            db.scalars(select(Audit.action))
        )
    assert apply(access, value["preview_token"]).status_code == 409
    revoked = access["client"].post(
        "/api/v1/execution-access/preview",
        json={"operation": "revoke", "version": response.json()["version"], "grant_id": grant["id"]},
    )
    assert revoked.status_code == 200
    assert apply(access, revoked.json()["preview_token"]).json()["grants"] == []
    assert yaml.safe_load(access["path"].read_text()) == {"subjects": {}}


@pytest.mark.parametrize(
    "roles,mcp", [("viewer", False), ("operator,viewer", False), ("administrator,viewer", True)]
)
def test_access_management_is_human_administrator_only(access, roles, mcp):
    headers = {"x-roles": roles, "x-mcp": str(mcp).lower()}
    before = access["path"].read_bytes()
    assert access["client"].get("/api/v1/execution-access", headers=headers).status_code == 403
    assert (
        access["client"]
        .post(
            "/api/v1/execution-access/preview",
            headers=headers,
            json={**access["payload"], "version": "a" * 64},
        )
        .status_code
        == 403
    )
    assert (
        access["client"]
        .post(
            "/api/v1/execution-access/apply",
            headers=headers,
            json={"preview_token": "a" * 43, "confirmed": True, "reason": "Attempt unauthorized mutation"},
        )
        .status_code
        == 403
    )
    assert access["path"].read_bytes() == before


@pytest.mark.parametrize("change", ["foreign_admin", "expired", "stale_policy", "changed_test"])
def test_permission_review_rejects_substitution_expiry_and_changed_state(access, change):
    preview = prepare(access).json()
    headers = {}
    if change == "foreign_admin":
        headers = {"x-human": "admin-two"}
    elif change == "expired":
        access["app"].state.execution_access_previews[preview["preview_token"]]["expires_at"] = 0
    elif change == "stale_policy":
        access["path"].write_text("# another administrator changed the policy\nsubjects: {}\n")
    else:
        with access["app"].state.sessions() as db, db.begin():
            db.get(AtomicTest, access["payload"]["test_guid"]).content_hash = "b" * 64
            db.get(CatalogApproval, access["payload"]["test_guid"]).content_hash = "b" * 64
    before = access["path"].read_bytes()
    response = apply(access, preview["preview_token"], headers)
    assert response.status_code == 409, response.text
    assert access["path"].read_bytes() == before


@pytest.mark.parametrize(
    "override",
    [
        {"actor_id": str(uuid4())},
        {"profile_id": str(uuid4())},
        {"subject": "*"},
        {"actions": []},
        {"actions": ["administrator"]},
        {"risks": ["high"]},
    ],
)
def test_scope_cannot_be_broadened_or_forged(access, override):
    before = access["path"].read_bytes()
    assert prepare(access, **override).status_code == 422
    assert access["path"].read_bytes() == before


def test_confirmation_is_required_and_simulation_cannot_edit_real_policy(access):
    token = prepare(access).json()["preview_token"]
    assert (
        access["client"]
        .post(
            "/api/v1/execution-access/apply",
            json={"preview_token": token, "confirmed": False, "reason": "Not confirmed by administrator"},
        )
        .status_code
        == 422
    )
    before = access["path"].read_bytes()
    access["settings"].mode = "mock"
    assert access["client"].get("/api/v1/execution-access").json()["configured"] is False
    assert apply(access, token).status_code == 409
    assert access["path"].read_bytes() == before


def test_symlink_policy_is_not_edited(access):
    original = access["path"]
    link = original.with_name("linked.yaml")
    link.symlink_to(original)
    access["settings"].policy_file = str(link)
    assert access["client"].get("/api/v1/execution-access").status_code == 503
    assert yaml.safe_load(original.read_text()) == {"subjects": {}}


def test_file_write_failure_retains_policy_and_durable_audit_intent(access, monkeypatch):
    from apps.api.app.routes import execution_access

    token = prepare(access).json()["preview_token"]
    before = access["path"].read_bytes()

    def fail_write(*args):
        raise OSError("test write failure")

    monkeypatch.setattr(execution_access, "replace_policy", fail_write)
    response = apply(access, token)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "policy_write_failed"
    assert access["path"].read_bytes() == before
    with access["app"].state.sessions() as db:
        actions = set(db.scalars(select(Audit.action)))
        assert {"execution_access.intent", "execution_access.write_failed"} <= actions
        assert "execution_access.applied" not in actions


def test_blank_reason_and_duplicate_grants_are_refused(access):
    token = prepare(access).json()["preview_token"]
    assert (
        access["client"]
        .post(
            "/api/v1/execution-access/apply",
            json={"preview_token": token, "confirmed": True, "reason": " " * 20},
        )
        .status_code
        == 422
    )
    assert apply(access, token).status_code == 200
    assert prepare(access).status_code == 409


def test_concurrent_confirmations_cannot_overwrite_each_other(access):
    from concurrent.futures import ThreadPoolExecutor

    first = prepare(access).json()["preview_token"]
    second = prepare(access, subject="second-requester").json()["preview_token"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda token: apply(access, token), [first, second]))
    assert sorted(response.status_code for response in responses) == [200, 409]
    grants = access["client"].get("/api/v1/execution-access").json()["grants"]
    assert len(grants) == 1
