"""Explicit local Keycloak acceptance check; creates and removes an isolated temporary realm."""

import json
import os
import secrets
import ssl
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import httpx
from fastapi import HTTPException
from pydantic import SecretStr

from apps.api.app.config import Settings
from apps.api.app.db import factory, make_engine
from apps.api.app.models import Base, UserAccessState
from apps.api.app.routes.users import ChangeRoles, CreateUser, DeleteUser
from apps.api.app.services.users import change_roles, create, delete_user, get_user, list_users
from apps.local_identity.realm import USER_ROLES, build_realm
from apps.local_identity.runtime import environment
from apps.local_identity.user_management import CLIENT, provision_client


def main():
    values = environment()
    os.environ["SSL_CERT_FILE"] = values["SSL_CERT_FILE"]
    origin = values["ATOMIC_OIDC_ISSUER"].removesuffix("/realms/atomic-control")
    credentials = json.loads(Path("artifacts/keycloak/credentials.json").read_text())
    realm = "atomic-user-check-" + uuid4().hex[:12]
    owner = uuid4().hex
    secret = secrets.token_urlsafe(36)
    context = ssl.create_default_context(cafile=values["SSL_CERT_FILE"])
    with httpx.Client(verify=context, timeout=20, trust_env=False, follow_redirects=False) as admin:
        token = admin.post(
            origin + "/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "atomic-bootstrap",
                "password": credentials["bootstrap_password"],
            },
        )
        token.raise_for_status()
        admin.headers["Authorization"] = "Bearer " + token.json()["access_token"]
        temp = {
            "browser_secret": secrets.token_urlsafe(24),
            "mcp_secret": secrets.token_urlsafe(24),
            "users": {name: secrets.token_urlsafe(24) for name in USER_ROLES},
        }
        payload = build_realm(temp)
        payload.update(realm=realm, attributes={"atomic-control-owner": owner})
        response = admin.post(origin + "/admin/realms", json=payload)
        response.raise_for_status()
        base = origin + "/admin/realms/" + realm
        try:
            provision_client(admin, base, owner, secret)
            provision_client(admin, base, owner, secret)
            settings = Settings(
                oidc_issuer=origin + "/realms/" + realm,
                oidc_jwks_url=origin + "/realms/" + realm + "/protocol/openid-connect/certs",
                signing_key_file=values["ATOMIC_SIGNING_KEY_FILE"],
                user_management_provider="keycloak",
                keycloak_management_client_id=CLIENT,
                keycloak_management_client_secret=SecretStr(secret),
            )
            data = CreateUser(
                username="acceptance.operator",
                first_name="Acceptance",
                last_name="Operator",
                email="acceptance@example.test",
                access_level="operator",
                temporary_password=SecretStr(secrets.token_urlsafe(24)),
            )
            result = create(settings, data, "fixture:admin", "acceptance-request")
            assert result["roles"] == ["operator", "viewer"] and result["enabled"]
            user = admin.get(base + "/users/" + result["id"]).raise_for_status().json()
            assert "UPDATE_PASSWORD" in user["requiredActions"]
            assert create(settings, data, "fixture:admin", "acceptance-request")["id"] == result["id"]
            admin.put(base + "/users/" + result["id"], json={"enabled": False}).raise_for_status()
            assert create(settings, data, "fixture:admin", "acceptance-request")["enabled"] is False
            try:
                create(settings, data, "fixture:admin", "different-request")
            except HTTPException as error:
                assert error.status_code == 409
            else:
                raise AssertionError("Existing account was adopted")
            minimal = CreateUser(
                username="acceptance.viewer", temporary_password=SecretStr(secrets.token_urlsafe(24))
            )
            assert create(settings, minimal, "fixture:admin", "minimal-viewer")["roles"] == ["viewer"]
            privileged = CreateUser(
                username="acceptance.admin",
                access_level="administrator",
                temporary_password=SecretStr(secrets.token_urlsafe(24)),
            )
            assert set(create(settings, privileged, "fixture:admin", "application-admin")["roles"]) == {
                "viewer",
                "operator",
                "approver",
                "privileged_approver",
                "administrator",
            }
            with TemporaryDirectory(prefix="atomic-role-check-") as directory:
                engine = make_engine("sqlite:///" + str(Path(directory) / "roles.db"))
                Base.metadata.create_all(engine)
                sessions = factory(engine)
                actor = (
                    admin.get(base + "/users", params={"username": "atomic-admin", "exact": "true"})
                    .raise_for_status()
                    .json()[0]
                )
                target = get_user(settings, result["id"])
                updated = change_roles(
                    settings,
                    result["id"],
                    ChangeRoles(access_level="approver", expected_version=target["version"]),
                    actor["id"],
                    sessions,
                )
                assert updated["roles"] == ["approver", "privileged_approver", "viewer"]
                assert updated["enabled"] is False and updated["sessions_revoked"]
                actual = admin.get(base + "/users/" + result["id"]).raise_for_status().json()
                assert "UPDATE_PASSWORD" in actual["requiredActions"]
                with sessions() as db:
                    state = db.get(UserAccessState, result["id"])
                    assert not state.blocked and actual["notBefore"] == state.invalid_before
                assert len(list_users(settings, "acceptance", 50, 0)["items"]) == 3
                own = get_user(settings, actor["id"])
                try:
                    change_roles(
                        settings,
                        actor["id"],
                        ChangeRoles(access_level="viewer", expected_version=own["version"]),
                        actor["id"],
                        sessions,
                    )
                except HTTPException as error:
                    assert error.status_code == 409
                else:
                    raise AssertionError("Self-demotion was accepted")
                deletion = DeleteUser(
                    confirm_username=updated["username"], expected_version=updated["version"]
                )
                removed = delete_user(settings, result["id"], deletion, actor["id"], sessions)
                assert removed["deleted"]
                assert admin.get(base + "/users/" + result["id"]).status_code == 404
                with sessions() as db:
                    assert db.get(UserAccessState, result["id"]).blocked
                assert delete_user(settings, result["id"], deletion, actor["id"], sessions)["replayed"]
                replacement = create(settings, data, actor["id"], "replacement-after-deletion")
                assert replacement["id"] != result["id"]
                assert admin.get(base + "/users/" + replacement["id"]).status_code == 200
                try:
                    delete_user(
                        settings,
                        actor["id"],
                        DeleteUser(confirm_username=own["username"], expected_version=own["version"]),
                        actor["id"],
                        sessions,
                    )
                except HTTPException as error:
                    assert error.status_code == 409
                else:
                    raise AssertionError("Self-deletion was accepted")
                engine.dispose()
            print(
                "Verified in temporary Keycloak realm: creation, role editing, deletion, safe retries, username reuse, access revocation, disabled-account preservation and self-change protection."
            )
        finally:
            admin.delete(base).raise_for_status()
            print("Temporary realm removed; existing users unchanged.")


if __name__ == "__main__":
    main()
