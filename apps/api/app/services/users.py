"""Manage Keycloak human accounts through a dedicated, server-only management client."""

import hashlib
import hmac
import json
import ssl
import time
from contextlib import contextmanager
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
from fastapi import HTTPException

from ..errors import fail

ACCESS_LEVELS = {
    "viewer": {
        "label": "Viewer",
        "roles": ["viewer"],
        "description": "View actors, tests and execution evidence.",
    },
    "operator": {
        "label": "Operator",
        "roles": ["viewer", "operator"],
        "description": "View evidence and request approved tests, queues and cleanup.",
    },
    "approver": {
        "label": "Approver",
        "roles": ["viewer", "approver", "privileged_approver"],
        "description": "Review per-run requests, including privileged executions.",
    },
    "administrator": {
        "label": "Administrator",
        "roles": ["viewer", "operator", "approver", "privileged_approver", "administrator"],
        "description": "Manage users, catalog approvals, actors and application settings.",
    },
}
REQUEST_ATTRIBUTE = "atomic_control_request"
BINDING_ATTRIBUTE = "atomic_control_binding"
COMPLETE_ATTRIBUTE = "atomic_control_complete"
MANAGEMENT_ATTRIBUTES = [REQUEST_ATTRIBUTE, BINDING_ATTRIBUTE, COMPLETE_ATTRIBUTE]


def endpoints(settings):
    parsed = urlsplit(settings.oidc_issuer)
    parts = parsed.path.rstrip("/").rsplit("/realms/", 1)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
        or not parts[1]
        or "/" in parts[1]
    ):
        fail("user_management_unavailable", "Configure a Keycloak realm issuer for user management", 503)
    base = f"https://{parsed.netloc}{parts[0]}"
    return base + "/admin/realms/" + quote(parts[1], safe=""), settings.oidc_issuer.rstrip(
        "/"
    ) + "/protocol/openid-connect/token"


def configured(settings):
    return bool(
        settings.user_management_provider == "keycloak"
        and settings.keycloak_management_client_id
        and settings.keycloak_management_client_secret.get_secret_value()
    )


def options(settings):
    return {
        "available": configured(settings),
        "provider": "Keycloak" if settings.user_management_provider == "keycloak" else "",
        "message": ""
        if configured(settings)
        else "User creation is not configured. Configure the Keycloak user-management client on the control plane.",
        "minimum_password_length": 12,
        "temporary_password": True,
        "access_levels": [{"value": key, **value} for key, value in ACCESS_LEVELS.items()],
    }


def request_binding(settings, subject, key, data):
    if not key or len(key) > 128:
        fail("idempotency_required", "A 1–128 character Idempotency-Key is required", 422)
    secret = settings.keycloak_management_client_secret.get_secret_value().encode()
    operation = hmac.new(secret, json.dumps([subject, key]).encode(), hashlib.sha256).hexdigest()
    body = data.model_dump(mode="json", exclude={"temporary_password"})
    body["temporary_password"] = data.temporary_password.get_secret_value()
    binding = hmac.new(secret, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    return operation, binding


def create(settings, data, subject, key):
    if not configured(settings):
        fail("user_management_unavailable", options(settings)["message"], 503)
    base, token_url = endpoints(settings)
    operation, binding = request_binding(settings, subject, key, data)
    wanted = set(ACCESS_LEVELS[data.access_level]["roles"])
    # TLS remains verified and redirects are refused. Provider bodies/tokens/passwords never enter errors.
    try:
        with httpx.Client(
            verify=ssl.create_default_context(), timeout=15, follow_redirects=False, trust_env=False
        ) as http:
            token = http.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": settings.keycloak_management_client_id,
                    "client_secret": settings.keycloak_management_client_secret.get_secret_value(),
                },
            )
            if token.status_code != 200:
                fail("user_management_unavailable", "Keycloak user-management authentication failed", 503)
            http.headers["Authorization"] = "Bearer " + token.json()["access_token"]

            def call(method, path, **kwargs):
                response = http.request(method, base + path, **kwargs)
                if response.status_code >= 300:
                    fail(
                        "user_management_unavailable",
                        "Keycloak user management is temporarily unavailable. Retry the unchanged request",
                        503,
                    )
                return response

            def lookup():
                users = call("GET", "/users", params={"username": data.username, "exact": "true"}).json()
                if len(users) > 1:
                    fail("user_management_unavailable", "Keycloak returned an ambiguous username", 503)
                return users[0] if users else None

            clients = call("GET", "/clients", params={"clientId": settings.oidc_audience}).json()
            if len(clients) != 1:
                fail("user_management_unavailable", "Atomic Control role configuration is unavailable", 503)
            client_id = str(UUID(clients[0]["id"]))
            roles = call("GET", f"/clients/{client_id}/roles").json()
            role_map = {role["name"]: role for role in roles}
            if not wanted <= role_map.keys():
                fail("user_management_unavailable", "Atomic Control roles are missing in Keycloak", 503)
            user = lookup()
            replayed = bool(user)
            if not user:
                response = http.post(
                    base + "/users",
                    json={
                        "username": data.username,
                        "firstName": data.first_name,
                        "lastName": data.last_name,
                        "email": data.email or None,
                        "emailVerified": False,
                        "enabled": False,
                        "requiredActions": ["UPDATE_PASSWORD"],
                        "credentials": [
                            {
                                "type": "password",
                                "value": data.temporary_password.get_secret_value(),
                                "temporary": True,
                            }
                        ],
                        "attributes": {
                            REQUEST_ATTRIBUTE: [operation],
                            BINDING_ATTRIBUTE: [binding],
                            COMPLETE_ATTRIBUTE: ["false"],
                        },
                    },
                )
                if response.status_code == 400:
                    fail(
                        "user_rejected",
                        "Keycloak rejected the account details or password policy. Check the fields and try again",
                        422,
                    )
                if response.status_code not in {201, 409}:
                    fail(
                        "user_management_unavailable",
                        "User creation could not be confirmed. Retry the unchanged request",
                        503,
                    )
                user = lookup()
                if not user:
                    fail(
                        "user_management_unavailable",
                        "User creation could not be confirmed. Retry the unchanged request",
                        503,
                    )
            attributes = user.get("attributes", {})
            if attributes.get(REQUEST_ATTRIBUTE) != [operation] or attributes.get(BINDING_ATTRIBUTE) != [
                binding
            ]:
                fail("user_exists", "This username is already in use. Existing accounts are not changed", 409)
            user_id = str(UUID(user["id"]))
            assigned = call("GET", f"/users/{user_id}/role-mappings/clients/{client_id}").json()
            actual = {role["name"] for role in assigned}
            if actual - wanted:
                fail(
                    "user_creation_changed",
                    "This account was changed in Keycloak. Review it there before retrying",
                    409,
                )
            complete = attributes.get(COMPLETE_ATTRIBUTE) == ["true"]
            if not complete:
                if user.get("enabled"):
                    fail(
                        "user_creation_changed",
                        "This account was changed in Keycloak. Review it there before retrying",
                        409,
                    )
                call(
                    "POST",
                    f"/users/{user_id}/role-mappings/clients/{client_id}",
                    json=[role_map[name] for name in sorted(wanted)],
                )
                verified = call("GET", f"/users/{user_id}/role-mappings/clients/{client_id}").json()
                if {role["name"] for role in verified} != wanted:
                    fail(
                        "user_management_unavailable",
                        "Role assignment could not be confirmed. The account remains disabled; retry unchanged",
                        503,
                    )
                attributes[COMPLETE_ATTRIBUTE] = ["true"]
                call("PUT", f"/users/{user_id}", json={"enabled": True, "attributes": attributes})
            elif actual != wanted:
                fail(
                    "user_creation_changed",
                    "This account was changed in Keycloak. Review it there before retrying",
                    409,
                )
            return {
                "id": user_id,
                "username": user["username"],
                "roles": sorted(wanted),
                "access_level": data.access_level,
                "temporary_password": True,
                "enabled": user.get("enabled", False) if complete else True,
                "replayed": replayed,
            }
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        fail(
            "user_management_unavailable",
            "User creation could not be confirmed. Retry the unchanged request",
            503,
        )


class Directory:
    def __init__(self, http, base, settings):
        self.http, self.base = http, base
        self.deadline = time.monotonic() + 90
        clients = self.call("GET", "/clients", params={"clientId": settings.oidc_audience}).json()
        if len(clients) != 1:
            fail("user_management_unavailable", "Atomic Control role configuration is unavailable", 503)
        self.client_id = str(UUID(clients[0]["id"]))
        self.role_map = {
            role["name"]: role for role in self.call("GET", f"/clients/{self.client_id}/roles").json()
        }
        self.known = set(ACCESS_LEVELS["administrator"]["roles"])

    def call(self, method, path, **kwargs):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            fail("user_management_unavailable", "Keycloak user-management request timed out", 503)
        response = self.http.request(method, self.base + path, timeout=min(10, remaining), **kwargs)
        if response.status_code == 404:
            fail("not_found", "The user or role no longer exists", 404)
        if response.status_code >= 300:
            fail("user_management_unavailable", "Keycloak user management is temporarily unavailable", 503)
        return response

    def user(self, user_id):
        user = self.call("GET", f"/users/{quote(str(user_id), safe='')}").json()
        if user.get("serviceAccountClientId") or user.get("username", "").startswith("service-account-"):
            fail("user_not_editable", "Service accounts must be managed in Keycloak", 409)
        return user

    def mappings(self, user_id, effective=False):
        suffix = "/composite" if effective else ""
        return self.call(
            "GET", f"/users/{quote(str(user_id), safe='')}/role-mappings/clients/{self.client_id}{suffix}"
        ).json()

    def describe(self, user):
        from .common import fingerprint

        user_id = str(UUID(user["id"]))
        direct = self.mappings(user_id)
        effective = self.mappings(user_id, True)
        groups = self.call("GET", f"/users/{user_id}/groups", params={"first": 0, "max": 1}).json()
        direct_names = sorted(role["name"] for role in direct)
        roles = sorted(role["name"] for role in effective)
        editable = (
            not groups
            and not any(role.get("composite") for role in direct)
            and set(roles) == set(direct_names)
            and set(roles) <= self.known
        )
        return {
            "id": user_id,
            "username": user["username"],
            "first_name": user.get("firstName", ""),
            "last_name": user.get("lastName", ""),
            "email": user.get("email", ""),
            "enabled": bool(user.get("enabled")),
            "roles": roles,
            "direct_roles": direct_names,
            "access_level": next(
                (key for key, level in ACCESS_LEVELS.items() if set(level["roles"]) == set(roles)), "custom"
            ),
            "editable": editable,
            "edit_reason": ""
            if editable
            else "Group, composite or custom role assignments must be managed in Keycloak.",
            "version": fingerprint(
                {
                    "id": user_id,
                    "username": user["username"],
                    "enabled": bool(user.get("enabled")),
                    "direct": sorted(
                        ({key: role.get(key) for key in ("id", "name", "composite")} for role in direct),
                        key=lambda role: role["name"],
                    ),
                    "effective": roles,
                    "groups": sorted(group["id"] for group in groups),
                }
            ),
        }

    def require_admin(self, subject):
        if not self.user(subject).get("enabled"):
            fail("forbidden", "Your account is disabled. Sign in again", 403)
        if "administrator" not in {role["name"] for role in self.mappings(subject, True)}:
            fail("forbidden", "Your administrator role has changed. Sign in again", 403)


@contextmanager
def directory(settings):
    if not configured(settings):
        fail("user_management_unavailable", options(settings)["message"], 503)
    base, token_url = endpoints(settings)
    try:
        with httpx.Client(
            verify=ssl.create_default_context(), timeout=10, trust_env=False, follow_redirects=False
        ) as http:
            response = http.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": settings.keycloak_management_client_id,
                    "client_secret": settings.keycloak_management_client_secret.get_secret_value(),
                },
            )
            if response.status_code != 200:
                fail("user_management_unavailable", "Keycloak user-management authentication failed", 503)
            http.headers["Authorization"] = "Bearer " + response.json()["access_token"]
            yield Directory(http, base, settings)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        fail("user_management_unavailable", "Keycloak user management is temporarily unavailable", 503)


def list_users(settings, query, limit, offset):
    with directory(settings) as provider:
        rows = provider.call("GET", "/users", params={"search": query, "first": offset, "max": limit}).json()
        humans = [
            row
            for row in rows
            if not row.get("serviceAccountClientId")
            and not row.get("username", "").startswith("service-account-")
        ]
        return {
            "items": [provider.describe(row) for row in humans],
            "offset": offset,
            "next_offset": offset + len(rows),
            "has_more": len(rows) == limit,
        }


def get_user(settings, user_id):
    with directory(settings) as provider:
        return provider.describe(provider.user(user_id))


def change_roles(settings, user_id, data, subject, sessions):
    import time

    from ..models import UserAccessState
    from . import user_access
    from .common import audit

    owner = user_access.acquire(sessions)
    held = False
    try:
        with directory(settings) as provider:
            provider.require_admin(subject)
            target = provider.describe(provider.user(user_id))
            if not target["editable"]:
                fail("user_not_editable", target["edit_reason"], 409)
            wanted = sorted(ACCESS_LEVELS[data.access_level]["roles"])
            if str(user_id) == subject and "administrator" not in wanted:
                fail("self_demotion", "Another administrator must change your administrator access", 409)
            if not set(wanted) <= provider.role_map.keys():
                fail("user_management_unavailable", "Atomic Control roles are missing in Keycloak", 503)
            with sessions() as db:
                state = db.get(UserAccessState, str(user_id))
                blocked = bool(state and state.blocked)
            if target["version"] != data.expected_version and target["roles"] != wanted:
                fail("user_roles_changed", "This user's roles changed. Refresh the user before saving", 409)
            if target["roles"] == wanted and not blocked:
                return {**target, "changed": False, "sessions_revoked": False, "access_on_hold": False}
            if str(user_id) == subject:
                fail("self_role_change", "Another administrator must change your roles", 409)
            before = target["roles"]
            user_access.hold(sessions, owner, str(user_id), subject, before, wanted)
            held = True
            path = f"/users/{user_id}/role-mappings/clients/{provider.client_id}"
            removed, added = set(before) - set(wanted), set(wanted) - set(before)
            if removed:
                provider.call("DELETE", path, json=[provider.role_map[name] for name in sorted(removed)])
            if added:
                provider.call("POST", path, json=[provider.role_map[name] for name in sorted(added)])
            result = provider.describe(provider.user(user_id))
            if result["roles"] != wanted or result["direct_roles"] != wanted:
                fail(
                    "user_roles_unverified",
                    "Role changes could not be verified. Refresh and retry; account access is on hold",
                    503,
                )
            # Keycloak logout advances user not-before; the profile PUT does not set it.
            # Cross the issuance-second boundary so every pre-change token is older.
            cutoff = int(time.time()) + 1
            time.sleep(max(0, cutoff - time.time()) + 0.02)
            provider.call("POST", f"/users/{user_id}/logout")
            provider_cutoff = int(provider.user(user_id).get("notBefore", 0))
            if provider_cutoff < cutoff:
                fail("user_roles_unverified", "Session revocation could not be verified", 503)
            user_access.finish(sessions, owner, str(user_id), subject, before, wanted, provider_cutoff)
            return {**result, "changed": True, "sessions_revoked": True, "access_on_hold": False}
    except Exception as error:
        if held:
            with sessions() as db, db.begin():
                audit(db, subject, "user.roles_change_incomplete", str(user_id))
            if isinstance(error, HTTPException):
                fail(
                    "user_roles_incomplete",
                    "Role update is incomplete and account access is on hold. Refresh the user and retry",
                    503,
                )
        raise
    finally:
        user_access.release(sessions, owner)


def delete_user(settings, user_id, data, subject, sessions):
    """Delete an exact human identity while retaining its local access tombstone and evidence."""
    from sqlalchemy import select

    from ..models import Audit, UserAccessState
    from . import user_access
    from .common import audit

    user_id = str(user_id)
    if user_id == subject:
        fail("self_deletion", "You cannot delete your own account. Ask another administrator", 409)
    owner = user_access.acquire(sessions)
    held = False

    def completed(replayed=False):
        with sessions() as db, db.begin():
            audit(db, subject, "user.deleted", user_id, username=data.confirm_username, replayed=replayed)
        return {"id": user_id, "username": data.confirm_username, "deleted": True, "replayed": replayed}

    try:
        with directory(settings) as provider:
            provider.require_admin(subject)
            try:
                target = provider.describe(provider.user(user_id))
            except HTTPException as error:
                if error.status_code != 404:
                    raise
                # Recover only a previously reviewed deletion of this UUID, never a reused username.
                with sessions() as db:
                    state = db.get(UserAccessState, user_id)
                    intents = db.scalars(
                        select(Audit).where(
                            Audit.action == "user.deletion_requested", Audit.resource == user_id
                        )
                    )
                    reviewed = any(
                        event.details.get("username") == data.confirm_username
                        and event.details.get("expected_version") == data.expected_version
                        for event in intents
                    )
                    if not (state and state.blocked and reviewed):
                        raise error
                return completed(replayed=True)
            if data.confirm_username != target["username"]:
                fail("user_confirmation_mismatch", "Enter the exact username to confirm deletion", 422)
            if data.expected_version != target["version"]:
                fail("user_changed", "This account changed. Refresh the user before deleting", 409)
            user_access.hold(
                sessions,
                owner,
                user_id,
                subject,
                target["roles"],
                [],
                action="user.deletion_requested",
                username=target["username"],
                expected_version=data.expected_version,
            )
            held = True
            provider.call("DELETE", f"/users/{user_id}")
            try:
                provider.call("GET", f"/users/{user_id}")
            except HTTPException as error:
                if error.status_code != 404:
                    raise
            else:
                fail("user_deletion_unverified", "User deletion could not be verified", 503)
            # Keep the durable hold: even an unexpired signed token for the deleted UUID is denied.
            return completed()
    except Exception as error:
        if held:
            with sessions() as db, db.begin():
                audit(db, subject, "user.deletion_incomplete", user_id, username=data.confirm_username)
            if isinstance(error, (HTTPException, httpx.HTTPError)):
                fail(
                    "user_deletion_incomplete",
                    "Deletion could not be confirmed. Account access is on hold; retry the same deletion or refresh users",
                    503,
                )
        raise
    finally:
        user_access.release(sessions, owner)
