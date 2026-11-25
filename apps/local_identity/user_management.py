"""Provision the owned Keycloak user-management client without rewriting deployment settings."""

import json
import os
import secrets
import ssl
import stat
from pathlib import Path

import httpx
from dotenv import dotenv_values

from apps.api.app.services.users import MANAGEMENT_ATTRIBUTES

from .realm import REALM, audience, mapper
from .setup import RUNTIME, private_write

CLIENT = "atomic-control-user-management"
SCOPE = "atomic-user-management-claims"
MANAGEMENT_ROLES = ["manage-users", "view-clients"]


def secure_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("User-management configuration must remain owner-only")


def provision_client(http, base, owner, secret):
    realm = http.get(base).raise_for_status().json()
    if realm.get("attributes", {}).get("atomic-control-owner") != owner:
        raise ValueError("Refusing an unrelated Keycloak realm")
    scopes = http.get(base + "/client-scopes").raise_for_status().json()
    scope = next((item for item in scopes if item["name"] == SCOPE), None)
    scope_data = {
        "name": SCOPE,
        "protocol": "openid-connect",
        "attributes": {"atomic-control-owner": owner, "include.in.token.scope": "false"},
        "protocolMappers": [
            audience("realm-management"),
            mapper(
                "user-management-roles",
                "oidc-usermodel-client-role-mapper",
                {
                    "usermodel.clientRoleMapping.clientId": "realm-management",
                    "claim.name": "resource_access.realm-management.roles",
                    "jsonType.label": "String",
                    "multivalued": "true",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            ),
        ],
    }
    if scope:
        if scope.get("attributes", {}).get("atomic-control-owner") != owner:
            raise ValueError("Refusing an unrelated management scope")
    else:
        http.post(base + "/client-scopes", json=scope_data).raise_for_status()
    clients = http.get(base + "/clients", params={"clientId": CLIENT}).raise_for_status().json()
    desired = {
        "clientId": CLIENT,
        "name": "Atomic Control user management",
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": secret,
        "enabled": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "fullScopeAllowed": False,
        "defaultClientScopes": ["basic", SCOPE, "kc-admin-api"],
        "optionalClientScopes": [],
        "attributes": {"atomic-control-owner": owner},
    }
    if clients:
        if len(clients) != 1 or clients[0].get("attributes", {}).get("atomic-control-owner") != owner:
            raise ValueError("Refusing an unrelated management client")
        client = clients[0]
        # Keep this owned client's secret aligned with its private configuration, including rotation.
        desired["attributes"] = {**client.get("attributes", {}), **desired["attributes"]}
        http.put(base + "/clients/" + client["id"], json=desired).raise_for_status()
    else:
        http.post(base + "/clients", json=desired).raise_for_status()
        client = http.get(base + "/clients", params={"clientId": CLIENT}).raise_for_status().json()[0]
    management = (
        http.get(base + "/clients", params={"clientId": "realm-management"}).raise_for_status().json()[0]
    )
    roles = {
        role["name"]: role
        for role in http.get(base + f"/clients/{management['id']}/roles").raise_for_status().json()
    }
    grants = [roles[name] for name in MANAGEMENT_ROLES]
    account = http.get(base + f"/clients/{client['id']}/service-account-user").raise_for_status().json()
    http.post(
        base + f"/users/{account['id']}/role-mappings/clients/{management['id']}", json=grants
    ).raise_for_status()
    http.post(
        base + f"/clients/{client['id']}/scope-mappings/clients/{management['id']}", json=grants
    ).raise_for_status()
    # Admin-only markers make lost-acknowledgement retries identifiable without storing passwords.
    profile = http.get(base + "/users/profile").raise_for_status().json()
    attributes = profile.setdefault("attributes", [])
    for name in MANAGEMENT_ATTRIBUTES:
        existing = next((item for item in attributes if item["name"] == name), None)
        expected = {"name": name, "multivalued": False, "permissions": {"view": ["admin"], "edit": ["admin"]}}
        if existing and any(existing.get(field) != value for field, value in expected.items()):
            raise ValueError("An incompatible user-management profile attribute already exists")
        if not existing:
            attributes.append(expected)
    http.put(base + "/users/profile", json=profile).raise_for_status()
    return client["id"]


def enable(runtime=RUNTIME, http=None):
    runtime = Path(runtime)
    for name in ["credentials.json", "application.env"]:
        secure_file(runtime / name)
    credentials = json.loads((runtime / "credentials.json").read_text())
    values = dotenv_values(runtime / "application.env", interpolate=False)
    issuer = (values.get("ATOMIC_OIDC_ISSUER") or "").rstrip("/")
    if not issuer.endswith("/realms/" + REALM) or not issuer.startswith("https://"):
        raise ValueError("Expected the owned Atomic Control Keycloak issuer")
    origin = issuer.removesuffix("/realms/" + REALM)
    if "user_management_secret" not in credentials:
        credentials["user_management_secret"] = secrets.token_urlsafe(36)
        private_write(runtime / "credentials.json", (json.dumps(credentials, indent=2) + "\n").encode())
    secret = credentials["user_management_secret"]

    def configure(http):
        provision_client(http, origin + "/admin/realms/" + REALM, credentials["owner_id"], secret)

    if http is not None:
        configure(http)
    else:
        with httpx.Client(
            verify=ssl.create_default_context(cafile=str(runtime / "tls/ca-bundle.pem")),
            timeout=15,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.post(
                origin + "/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "atomic-bootstrap",
                    "password": credentials["bootstrap_password"],
                },
            )
            response.raise_for_status()
            client.headers["Authorization"] = "Bearer " + response.json()["access_token"]
            configure(client)
    changes = {
        "ATOMIC_USER_MANAGEMENT_PROVIDER": "keycloak",
        "ATOMIC_KEYCLOAK_MANAGEMENT_CLIENT_ID": CLIENT,
        "ATOMIC_KEYCLOAK_MANAGEMENT_CLIENT_SECRET": secret,
    }
    # Preserve every unrelated setting (addresses, network restrictions, approval mode, credentials).
    lines = (runtime / "application.env").read_text().splitlines()
    lines = [line for line in lines if line.split("=", 1)[0].strip() not in changes]
    lines.extend(key + "=" + json.dumps(value) for key, value in changes.items())
    private_write(runtime / "application.env", ("\n".join(lines) + "\n").encode())
    after = dotenv_values(runtime / "application.env", interpolate=False)
    if any(after.get(key) != value for key, value in values.items() if key not in changes):
        raise RuntimeError("An unrelated deployment setting changed")
    print("Configured Keycloak user management; restart the application runtime to load it.")
    print("Existing human accounts, passwords and application roles were preserved.")


if __name__ == "__main__":
    enable()
