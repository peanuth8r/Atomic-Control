"""Exercise user creation against an isolated Keycloak protocol fixture."""

import json
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from apps.api.app.auth import Principal, human
from apps.api.app.models import Audit
from apps.api.app.services import users

ADMIN = {"X-Test-User": "admin", "Idempotency-Key": "create-user-fixture"}
PASSWORD = "Fixture-only password 123!"
BODY = {
    "username": "new.operator",
    "first_name": "New",
    "last_name": "Operator",
    "email": "operator@example.test",
    "access_level": "operator",
    "temporary_password": PASSWORD,
}
CLIENT = str(uuid4())


@pytest.fixture
def provider(env, monkeypatch):
    settings = env["settings"]
    settings.oidc_issuer = "https://id.example.test/realms/atomic-control"
    settings.user_management_provider = "keycloak"
    settings.keycloak_management_client_id = "user-manager"
    settings.keycloak_management_client_secret = SecretStr("management-secret-fixture")
    state = {
        "users": [],
        "roles": {},
        "posts": [],
        "calls": [],
        "fail": "",
        "token": True,
        "creates": 0,
        "enables": 0,
        "groups": {},
        "effective": {},
        "caller_roles": users.ACCESS_LEVELS["administrator"]["roles"][:],
        "logouts": 0,
        "mutations": [],
        "deletes": 0,
    }
    actual_client = httpx.Client
    role_rows = [
        {"id": str(uuid4()), "name": name, "clientRole": True, "containerId": CLIENT}
        for name in users.ACCESS_LEVELS["administrator"]["roles"]
    ]

    def handle(request):
        path = request.url.path
        state["calls"].append((request.method, path))
        assert request.url.scheme == "https"
        if path.endswith("/protocol/openid-connect/token"):
            assert b"grant_type=client_credentials" in request.content
            return httpx.Response(
                200 if state["token"] else 401, json={"access_token": "fixture-management-token"}
            )
        assert request.headers["authorization"] == "Bearer fixture-management-token"
        if path.endswith("/clients"):
            return httpx.Response(200, json=[{"id": CLIENT, "clientId": "atomic-control"}])
        if path.endswith(f"/clients/{CLIENT}/roles"):
            return httpx.Response(200, json=role_rows)
        if path.endswith("/users/dev:admin"):
            return httpx.Response(200, json={"id": "dev:admin", "username": "fixture-admin", "enabled": True})
        if "/users/dev:admin/role-mappings/" in path:
            return httpx.Response(
                200, json=[role for role in role_rows if role["name"] in state["caller_roles"]]
            )
        if path.endswith("/users"):
            if request.method == "GET":
                if "username" in request.url.params:
                    matching = [
                        user
                        for user in state["users"]
                        if user["username"].casefold() == request.url.params["username"].casefold()
                    ]
                else:
                    search = request.url.params.get("search", "").casefold()
                    matching = [user for user in state["users"] if search in user["username"].casefold()]
                    first, maximum = (
                        int(request.url.params.get("first", 0)),
                        int(request.url.params.get("max", 20)),
                    )
                    matching = matching[first : first + maximum]
                return httpx.Response(200, json=matching)
            state["posts"].append(json.loads(request.content))
            if state["fail"] == "password":
                return httpx.Response(400, json={"errorMessage": PASSWORD})
            body = json.loads(request.content)
            if any(user["username"] == body["username"] for user in state["users"]):
                return httpx.Response(409)
            body.pop("credentials")
            body["id"] = str(uuid4())
            state["users"].append(body)
            state["roles"][body["id"]] = []
            state["creates"] += 1
            return httpx.Response(201)
        for user in state["users"]:
            if f"/users/{user['id']}/role-mappings/" in path:
                if request.method == "GET":
                    roles = (
                        state["effective"].get(user["id"], state["roles"][user["id"]])
                        if path.endswith("/composite")
                        else state["roles"][user["id"]]
                    )
                    return httpx.Response(200, json=roles)
                if state["fail"] == "mapping" or (state["fail"] == "add_roles" and request.method == "POST"):
                    return httpx.Response(503, text="private provider details " + PASSWORD)
                changing = json.loads(request.content)
                state["mutations"].append((request.method, user["id"], changing))
                if request.method == "DELETE":
                    removing = {role["name"] for role in changing}
                    state["roles"][user["id"]] = [
                        role for role in state["roles"][user["id"]] if role["name"] not in removing
                    ]
                else:
                    merged = {role["name"]: role for role in state["roles"][user["id"]]}
                    merged.update({role["name"]: role for role in changing})
                    state["roles"][user["id"]] = list(merged.values())
                return httpx.Response(204)
            if path.endswith(f"/users/{user['id']}/groups"):
                return httpx.Response(200, json=state["groups"].get(user["id"], []))
            if path.endswith(f"/users/{user['id']}/logout"):
                state["logouts"] += 1
                if state["fail"] == "logout":
                    return httpx.Response(503)
                import time

                user["notBefore"] = int(time.time())
                return httpx.Response(204)
            if path.endswith("/users/" + user["id"]) and request.method == "GET":
                return httpx.Response(200, json=user)
            if path.endswith("/users/" + user["id"]) and request.method == "DELETE":
                state["deletes"] += 1
                if state["fail"] == "delete":
                    return httpx.Response(503, text=PASSWORD)
                if state["fail"] != "delete-not-applied":
                    state["users"].remove(user)
                if state["fail"] == "lost-delete-ack":
                    raise httpx.ReadTimeout("fixture loss", request=request)
                return httpx.Response(204)
            if path.endswith("/users/" + user["id"]) and request.method == "PUT":
                body = json.loads(request.content)
                user.update(body)
                if "enabled" in body:
                    state["enables"] += 1
                if state["fail"] == "lost-enable-ack":
                    raise httpx.ReadTimeout("fixture loss", request=request)
                return httpx.Response(204)
        if request.method == "GET" and "/users/" in path:
            return httpx.Response(404)
        raise AssertionError((request.method, path))

    monkeypatch.setattr(
        users.httpx, "Client", lambda **kwargs: actual_client(transport=httpx.MockTransport(handle), **kwargs)
    )
    return state


def create(env, body=None, headers=None):
    return env["client"].post("/api/v1/admin/users", headers=headers or ADMIN, json=body or BODY)


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_user_creation_and_options_require_administrator(env, provider, role):
    headers = {"X-Test-User": role, "Idempotency-Key": "forbidden"}
    assert env["client"].get("/api/v1/admin/users/options", headers=headers).status_code == 403
    assert create(env, headers=headers).status_code == 403
    assert not provider["calls"]


def test_mcp_cannot_administer_users_even_with_administrator_role(env, provider):
    env["app"].dependency_overrides[human] = lambda: Principal(
        "delegated",
        frozenset({"viewer", "administrator"}),
        frozenset({"atomic:read", "atomic:request"}),
        True,
    )
    assert create(env).status_code == 403
    assert not provider["calls"]


def test_options_and_disabled_configuration(env):
    response = env["client"].get("/api/v1/admin/users/options", headers=ADMIN)
    assert response.status_code == 200
    assert response.json()["available"] is False
    assert create(env).status_code == 503


def test_user_gets_exact_application_roles_and_temporary_password_without_secret_storage(env, provider):
    response = create(env)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["roles"] == ["operator", "viewer"]
    assert result["enabled"] and result["temporary_password"]
    assert provider["posts"][0]["enabled"] is False
    assert provider["posts"][0]["requiredActions"] == ["UPDATE_PASSWORD"]
    assert provider["posts"][0]["credentials"] == [{"type": "password", "value": PASSWORD, "temporary": True}]
    assert "management-secret-fixture" not in response.text and PASSWORD not in response.text
    with env["app"].state.sessions() as db:
        audits = list(db.scalars(select(Audit).where(Audit.action.like("user.%"))))
        assert [audit.action for audit in audits] == ["user.creation_requested", "user.created"]
        serialized = json.dumps([audit.details for audit in audits])
        assert PASSWORD not in serialized and "management-secret-fixture" not in serialized


def test_same_key_retry_does_not_create_reset_or_enable_account_twice(env, provider):
    first = create(env).json()
    second = create(env)
    assert second.status_code == 201
    assert second.json()["id"] == first["id"]
    assert second.json()["replayed"]
    assert provider["creates"] == provider["enables"] == 1
    assert len(provider["posts"]) == 1


def test_existing_username_is_never_adopted_or_modified(env, provider):
    provider["users"].append(
        {"id": str(uuid4()), "username": BODY["username"], "enabled": True, "attributes": {}}
    )
    response = create(env)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "user_exists"
    assert not provider["posts"] and not provider["enables"]


def test_changed_payload_or_new_operation_cannot_mutate_existing_account(env, provider):
    create(env).raise_for_status()
    assert create(env, body={**BODY, "access_level": "administrator"}).status_code == 409
    assert create(env, headers={**ADMIN, "Idempotency-Key": "different"}).status_code == 409
    assert provider["enables"] == 1


def test_role_assignment_failure_leaves_disabled_account_and_retry_recovers(env, provider):
    provider["fail"] = "mapping"
    response = create(env)
    assert response.status_code == 503
    assert PASSWORD not in response.text and "private provider details" not in response.text
    assert provider["users"][0]["enabled"] is False
    provider["fail"] = ""
    response = create(env)
    assert response.status_code == 201 and response.json()["enabled"]
    assert provider["creates"] == provider["enables"] == 1


def test_lost_enable_acknowledgement_recovers_without_mutating_account(env, provider):
    provider["fail"] = "lost-enable-ack"
    assert create(env).status_code == 503
    assert provider["users"][0]["enabled"]
    provider["fail"] = ""
    response = create(env)
    assert response.status_code == 201 and response.json()["replayed"]
    assert provider["enables"] == provider["creates"] == 1


def test_replay_does_not_reenable_externally_disabled_account(env, provider):
    create(env).raise_for_status()
    provider["users"][0]["enabled"] = False
    response = create(env)
    assert response.status_code == 201
    assert response.json()["enabled"] is False
    assert provider["enables"] == 1


def test_provider_password_policy_rejection_is_sanitized(env, provider):
    provider["fail"] = "password"
    response = create(env)
    assert response.status_code == 422
    assert PASSWORD not in response.text
    assert not provider["users"]


def test_invalid_details_rejected_without_contacting_provider(env, provider):
    for changes in [
        {"temporary_password": "short"},
        {"access_level": "realm-admin"},
        {"roles": ["administrator"]},
        {"username": "service-account-pretend"},
        {"email": "broken-email"},
    ]:
        response = create(env, body={**BODY, **changes})
        assert response.status_code == 422
        assert PASSWORD not in response.text
    assert not provider["calls"]


def test_management_token_failure_does_not_attempt_user_creation(env, provider):
    provider["token"] = False
    assert create(env).status_code == 503
    assert not provider["users"] and len(provider["calls"]) == 1


def test_cross_origin_creation_refused(env, provider):
    assert create(env, headers={**ADMIN, "Origin": "https://other.example.test"}).status_code == 403
    assert not provider["calls"]


def test_unexpected_existing_roles_are_not_overwritten(env, provider):
    provider["fail"] = "mapping"
    assert create(env).status_code == 503
    provider["fail"] = ""
    user = provider["users"][0]
    provider["roles"][user["id"]] = [{"name": "unexpected-role"}]
    assert create(env).status_code == 409
    assert not user["enabled"] and provider["enables"] == 0


def user_detail(env, user_id):
    response = env["client"].get(f"/api/v1/admin/users/{user_id}", headers=ADMIN)
    assert response.status_code == 200, response.text
    return response.json()


def change_roles(env, user_id, level, version=None, headers=None):
    version = version or user_detail(env, user_id)["version"]
    return env["client"].post(
        f"/api/v1/admin/users/{user_id}/roles",
        headers=headers or ADMIN,
        json={"access_level": level, "expected_version": version},
    )


def test_administrator_lists_searches_and_reads_humans_only(env, provider):
    created = create(env).json()
    provider["users"].append(
        {
            "id": str(uuid4()),
            "username": "service-account-internal",
            "enabled": True,
            "serviceAccountClientId": "internal",
        }
    )
    response = env["client"].get("/api/v1/admin/users?limit=20&q=new", headers=ADMIN)
    assert response.status_code == 200, response.text
    assert [user["id"] for user in response.json()["items"]] == [created["id"]]
    assert user_detail(env, created["id"])["access_level"] == "operator"
    response = env["client"].get("/api/v1/admin/users?limit=20", headers=ADMIN)
    assert len(response.json()["items"]) == 1
    assert PASSWORD not in response.text


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_other_roles_cannot_list_or_edit_users(env, provider, role):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    headers = {"X-Test-User": role}
    assert env["client"].get("/api/v1/admin/users", headers=headers).status_code == 403
    assert env["client"].get(f"/api/v1/admin/users/{user_id}", headers=headers).status_code == 403
    assert change_roles(env, user_id, "administrator", version, headers).status_code == 403


def test_mcp_cannot_edit_existing_users(env, provider):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    env["app"].dependency_overrides[human] = lambda: Principal(
        "delegated",
        frozenset({"viewer", "administrator"}),
        frozenset({"atomic:read", "atomic:request"}),
        True,
    )
    assert change_roles(env, user_id, "viewer", version).status_code == 403


def test_role_change_revokes_only_target_sessions_and_persists_auth_cutoff(env, provider):
    import time

    from apps.api.app.models import BrowserSession, UserAccessState

    user_id = create(env).json()["id"]
    with env["app"].state.sessions() as db, db.begin():
        for key, subject in [("a" * 64, user_id), ("b" * 64, "other-subject")]:
            db.add(
                BrowserSession(
                    id=key,
                    subject=subject,
                    encrypted_tokens="fixture",
                    expires_at=time.time() + 86400,
                    access_expires_at=time.time() + 300,
                )
            )
    old_actions = provider["users"][0]["requiredActions"][:]
    response = change_roles(env, user_id, "approver")
    assert response.status_code == 200, response.text
    assert response.json()["roles"] == ["approver", "privileged_approver", "viewer"]
    assert response.json()["sessions_revoked"]
    assert provider["users"][0]["requiredActions"] == old_actions
    assert provider["users"][0]["enabled"]
    assert provider["users"][0]["notBefore"] >= int(time.time())
    assert provider["logouts"] == 1
    with env["app"].state.sessions() as db:
        assert db.get(BrowserSession, "a" * 64) is None
        assert db.get(BrowserSession, "b" * 64) is not None
        assert not db.get(UserAccessState, user_id).blocked
        event = db.scalar(select(Audit).where(Audit.action == "user.roles_updated"))
        assert event.details["before"] == ["operator", "viewer"]
        assert event.details["after"] == response.json()["roles"]


def test_stale_role_preview_fails_without_changing_access(env, provider):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    provider["roles"][user_id] = [{"id": str(uuid4()), "name": "viewer"}]
    before = len(provider["mutations"])
    response = change_roles(env, user_id, "administrator", version)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "user_roles_changed"
    assert len(provider["mutations"]) == before and provider["logouts"] == 0


def test_role_change_retry_is_noop_and_disabled_state_is_preserved(env, provider):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    provider["users"][0]["enabled"] = False
    version = user_detail(env, user_id)["version"]
    response = change_roles(env, user_id, "viewer", version)
    assert response.status_code == 200 and not response.json()["enabled"]
    count = len(provider["mutations"])
    response = change_roles(env, user_id, "viewer", version)
    assert response.status_code == 200 and response.json()["changed"] is False
    assert len(provider["mutations"]) == count and provider["logouts"] == 1


def test_self_demotion_is_refused(env, provider):
    user_id = create(env, body={**BODY, "access_level": "administrator"}).json()["id"]
    version = user_detail(env, user_id)["version"]
    env["app"].dependency_overrides[human] = lambda: Principal(
        user_id, frozenset({"viewer", "administrator"}), frozenset()
    )
    response = change_roles(env, user_id, "viewer", version)
    assert response.status_code == 409 and response.json()["error"]["code"] == "self_demotion"


def test_stale_administrator_claim_cannot_change_roles(env, provider):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    provider["caller_roles"] = ["viewer"]
    response = change_roles(env, user_id, "administrator", version)
    assert response.status_code == 403 and provider["logouts"] == 0


def test_incomplete_role_change_holds_access_and_can_be_repaired(env, provider):
    from apps.api.app.models import UserAccessState

    user_id = create(env).json()["id"]
    provider["fail"] = "add_roles"
    response = change_roles(env, user_id, "approver")
    assert response.status_code == 503
    with env["app"].state.sessions() as db:
        assert db.get(UserAccessState, user_id).blocked
    current = user_detail(env, user_id)
    assert current["access_on_hold"] and current["roles"] == ["viewer"]
    provider["fail"] = ""
    response = change_roles(env, user_id, "approver", current["version"])
    assert response.status_code == 200 and not response.json()["access_on_hold"]
    with env["app"].state.sessions() as db:
        assert not db.get(UserAccessState, user_id).blocked


@pytest.mark.parametrize("kind", ["group", "composite", "custom"])
def test_inherited_or_custom_assignments_require_keycloak(env, provider, kind):
    user_id = create(env).json()["id"]
    if kind == "group":
        provider["groups"][user_id] = [{"id": str(uuid4())}]
    elif kind == "composite":
        provider["roles"][user_id][0]["composite"] = True
    else:
        provider["roles"][user_id].append({"id": str(uuid4()), "name": "custom-role"})
    current = user_detail(env, user_id)
    assert not current["editable"]
    response = change_roles(env, user_id, "viewer", current["version"])
    assert response.status_code == 409 and provider["logouts"] == 0


def test_arbitrary_role_payloads_rejected(env, provider):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    response = env["client"].post(
        f"/api/v1/admin/users/{user_id}/roles",
        headers=ADMIN,
        json={"access_level": "realm-admin", "expected_version": version},
    )
    assert response.status_code == 422


def test_role_update_lease_serializes_operations(env, provider):
    from apps.api.app.services import user_access

    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    owner = user_access.acquire(env["app"].state.sessions)
    try:
        response = change_roles(env, user_id, "viewer", version)
        assert response.status_code == 409 and response.json()["error"]["code"] == "user_roles_busy"
    finally:
        user_access.release(env["app"].state.sessions, owner)
    assert change_roles(env, user_id, "viewer", version).status_code == 200


def test_revocation_rejects_old_tokens_and_survives_new_app(env, provider, monkeypatch):
    import time

    from fastapi.testclient import TestClient

    from apps.api.app import auth
    from apps.api.app.main import create_app
    from apps.api.app.models import UserAccessState

    user_id = create(env).json()["id"]
    assert change_roles(env, user_id, "viewer").status_code == 200
    with env["app"].state.sessions() as db:
        cutoff = db.get(UserAccessState, user_id).invalid_before
    claims = {
        "sub": user_id,
        "iat": cutoff - 1,
        "exp": time.time() + 300,
        "roles": ["viewer", "administrator"],
        "scope": "openid",
    }
    monkeypatch.setattr(auth, "verify_oidc", lambda *_: dict(claims))
    env["app"].dependency_overrides.clear()
    headers = {"Authorization": "Bearer fixture"}
    assert env["client"].get("/api/v1/me", headers=headers).status_code == 401
    app = create_app(env["settings"])
    client = TestClient(app)
    assert client.get("/api/v1/me", headers=headers).status_code == 401
    claims.update(iat=cutoff, roles=["viewer"])
    assert client.get("/api/v1/me", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
    app.state.engine.dispose()


def test_logout_failure_keeps_access_on_hold_until_repaired(env, provider):
    from apps.api.app.models import UserAccessState

    user_id = create(env).json()["id"]
    provider["fail"] = "logout"
    response = change_roles(env, user_id, "viewer")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "user_roles_incomplete"
    current = user_detail(env, user_id)
    assert current["roles"] == ["viewer"] and current["access_on_hold"]
    provider["fail"] = ""
    response = change_roles(env, user_id, "viewer", current["version"])
    assert response.status_code == 200 and response.json()["sessions_revoked"]
    with env["app"].state.sessions() as db:
        assert not db.get(UserAccessState, user_id).blocked


def test_access_hold_blocks_even_freshly_issued_tokens(env, provider, monkeypatch):
    import time

    from apps.api.app import auth

    user_id = create(env).json()["id"]
    provider["fail"] = "add_roles"
    assert change_roles(env, user_id, "administrator").status_code == 503
    monkeypatch.setattr(
        auth,
        "verify_oidc",
        lambda *_: {
            "sub": user_id,
            "iat": int(time.time()) + 10,
            "roles": ["viewer", "administrator"],
            "scope": "openid",
        },
    )
    env["app"].dependency_overrides.clear()
    assert env["client"].get("/api/v1/me", headers={"Authorization": "Bearer fixture"}).status_code == 401


def delete_user(env, user_id, version, username=BODY["username"], headers=None):
    return env["client"].request(
        "DELETE",
        f"/api/v1/admin/users/{user_id}",
        headers=headers or ADMIN,
        json={"expected_version": version, "confirm_username": username},
    )


def test_deletion_removes_account_sessions_but_preserves_history_and_token_hold(
    env, provider, monkeypatch, request_job
):
    import time

    from fastapi.testclient import TestClient

    from apps.api.app import auth
    from apps.api.app.main import create_app
    from apps.api.app.models import BrowserSession, Run, UserAccessState

    user_id = create(env).json()["id"]
    current = user_detail(env, user_id)
    historical = request_job().json()["run_id"]
    with env["app"].state.sessions() as db, db.begin():
        db.get(Run, historical).requested_by = user_id
        for key, subject in [("a" * 64, user_id), ("b" * 64, "other-subject")]:
            db.add(
                BrowserSession(
                    id=key,
                    subject=subject,
                    encrypted_tokens="fixture",
                    expires_at=time.time() + 86400,
                    access_expires_at=time.time() + 300,
                )
            )
        runs_before = list(db.scalars(select(Run.id)))
    response = delete_user(env, user_id, current["version"])
    assert response.status_code == 200, response.text
    assert response.json()["deleted"] and not provider["users"]
    with env["app"].state.sessions() as db:
        assert db.get(BrowserSession, "a" * 64) is None
        assert db.get(BrowserSession, "b" * 64) is not None
        assert db.get(UserAccessState, user_id).blocked
        assert list(db.scalars(select(Run.id))) == runs_before
        assert db.get(Run, historical).requested_by == user_id
        actions = list(db.scalars(select(Audit.action).where(Audit.resource == user_id)))
        assert "user.deletion_requested" in actions and "user.deleted" in actions
    monkeypatch.setattr(
        auth,
        "verify_oidc",
        lambda *_: {
            "sub": user_id,
            "iat": int(time.time()) + 10,
            "roles": ["viewer", "administrator"],
            "scope": "openid",
        },
    )
    env["app"].dependency_overrides.clear()
    assert (
        env["client"].get("/api/v1/me", headers={"Authorization": "Bearer deleted-fixture"}).status_code
        == 401
    )
    restarted = create_app(env["settings"])
    with TestClient(restarted) as client:
        assert (
            client.get("/api/v1/me", headers={"Authorization": "Bearer deleted-fixture"}).status_code == 401
        )
    restarted.state.engine.dispose()


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_deletion_requires_administrator(env, provider, role):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    assert delete_user(env, user_id, version, headers={"X-Test-User": role}).status_code == 403
    assert provider["deletes"] == 0


def test_mcp_cannot_delete_users(env, provider):
    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    env["app"].dependency_overrides[human] = lambda: Principal(
        "delegated",
        frozenset({"viewer", "administrator"}),
        frozenset({"atomic:read", "atomic:request"}),
        True,
    )
    assert delete_user(env, user_id, version).status_code == 403
    assert provider["deletes"] == 0


def test_self_deletion_is_refused(env, provider):
    user_id = create(env, body={**BODY, "access_level": "administrator"}).json()["id"]
    version = user_detail(env, user_id)["version"]
    env["app"].dependency_overrides[human] = lambda: Principal(
        user_id, frozenset({"viewer", "administrator"}), frozenset()
    )
    response = delete_user(env, user_id, version)
    assert response.status_code == 409 and response.json()["error"]["code"] == "self_deletion"
    assert provider["deletes"] == 0


@pytest.mark.parametrize("case", ["confirmation", "stale", "service", "stale-admin", "origin", "busy"])
def test_deletion_guards_leave_target_untouched(env, provider, case):
    from apps.api.app.models import UserAccessState
    from apps.api.app.services import user_access

    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    username, headers, owner = BODY["username"], ADMIN.copy(), None
    if case == "confirmation":
        username = "wrong-account"
    if case == "stale":
        provider["users"][0]["enabled"] = False
    if case == "service":
        provider["users"][0]["serviceAccountClientId"] = "internal"
    if case == "stale-admin":
        provider["caller_roles"] = ["viewer"]
    if case == "origin":
        headers["Origin"] = "https://other.example.test"
    if case == "busy":
        owner = user_access.acquire(env["app"].state.sessions)
    try:
        response = delete_user(env, user_id, version, username, headers)
        assert response.status_code in {403, 409, 422}, response.text
        assert provider["deletes"] == 0
        with env["app"].state.sessions() as db:
            assert db.get(UserAccessState, user_id) is None
    finally:
        if owner:
            user_access.release(env["app"].state.sessions, owner)


@pytest.mark.parametrize("failure", ["delete", "delete-not-applied", "lost-delete-ack"])
def test_unconfirmed_deletion_holds_access_and_same_request_recovers(env, provider, failure):
    from apps.api.app.models import UserAccessState

    user_id = create(env).json()["id"]
    version = user_detail(env, user_id)["version"]
    provider["fail"] = failure
    response = delete_user(env, user_id, version)
    assert response.status_code == 503 and response.json()["error"]["code"] == "user_deletion_incomplete"
    assert PASSWORD not in response.text
    with env["app"].state.sessions() as db:
        assert db.get(UserAccessState, user_id).blocked
    provider["fail"] = ""
    response = delete_user(env, user_id, version)
    assert response.status_code == 200 and response.json()["deleted"]
    assert not provider["users"]


def test_deletion_retry_is_bound_to_uuid_and_reviewed_request(env, provider):
    old_id = create(env).json()["id"]
    version = user_detail(env, old_id)["version"]
    assert delete_user(env, old_id, version).status_code == 200
    replacement = create(env, headers={**ADMIN, "Idempotency-Key": "replacement-account"}).json()["id"]
    assert replacement != old_id
    response = delete_user(env, old_id, version)
    assert response.status_code == 200 and response.json()["replayed"]
    assert provider["users"][0]["id"] == replacement
    assert delete_user(env, old_id, "f" * 64).status_code == 404
    assert delete_user(env, str(uuid4()), version).status_code == 404
    assert provider["deletes"] == 1


def test_group_account_can_be_deliberately_deleted(env, provider):
    user_id = create(env).json()["id"]
    provider["groups"][user_id] = [{"id": str(uuid4())}]
    target = user_detail(env, user_id)
    assert not target["editable"]
    assert delete_user(env, user_id, target["version"]).status_code == 200
