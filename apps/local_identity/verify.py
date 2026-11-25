"""Live Keycloak / real-mode API / MCP verification. Never starts an agent or an Atomic command."""

import asyncio
import hashlib
import json
import os
import secrets
import ssl
from base64 import urlsafe_b64encode
from contextlib import asynccontextmanager, contextmanager
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from uuid import uuid4

import httpx
import httpx2
import jwt
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from .realm import API, CODEX, CONTROL, ISSUER, MCP, USER_ROLES
from .runtime import environment
from .setup import KEYCLOAK, RUNTIME, private_write


def verify_browser_refresh(browser):
    """Force only this harness's temporary session through the real refresh path."""
    import time

    from apps.api.app.config import Settings
    from apps.api.app.db import factory, make_engine
    from apps.api.app.models import BrowserSession
    from apps.api.app.services.common import digest

    engine = make_engine(Settings().database_url)
    try:
        with factory(engine)() as db, db.begin():
            item = db.get(BrowserSession, digest(browser.cookies["atomic_session"]))
            assert item and item.expires_at > time.time() + 86300
            deadline, encrypted = item.expires_at, item.encrypted_tokens
            # The normal five-minute access-token boundary is also tested with a virtual clock.
            item.access_expires_at = time.time() - 1
        response = browser.get(CONTROL + "/api/v1/me")
        response.raise_for_status()
        assert response.json()["session_expires_at"] == deadline
        with factory(engine)() as db:
            item = db.get(BrowserSession, digest(browser.cookies["atomic_session"]))
            assert item and item.encrypted_tokens != encrypted and item.access_expires_at > time.time() + 200
        return {"real_provider_refresh": True, "fixed_24_hour_deadline": True}
    finally:
        engine.dispose()


TOKEN = ISSUER + "/protocol/openid-connect/token"
AUTH = ISSUER + "/protocol/openid-connect/auth"
CALLBACK = "http://127.0.0.1:1455/oauth/callback"


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.hidden = {}
        self.active = False

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "form" and data.get("id") == "kc-form-login":
            self.action, self.active = data.get("action"), True
        if tag == "input" and self.active and data.get("type") == "hidden" and data.get("name"):
            self.hidden[data["name"]] = data.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.active = False


def login_form(http, authorization_url, username, password):
    response = http.get(authorization_url)
    response.raise_for_status()
    parser = LoginForm()
    parser.feed(response.text)
    if not parser.action:
        raise RuntimeError("Keycloak did not return its username/password form")
    action = urljoin(authorization_url, parser.action)
    if urlsplit(action).netloc != urlsplit(KEYCLOAK).netloc or urlsplit(action).scheme != "https":
        raise ValueError("Login form action is not the configured HTTPS identity provider")
    result = http.post(
        action, data={**parser.hidden, "username": username, "password": password, "credentialId": ""}
    )
    if result.status_code not in {302, 303}:
        raise RuntimeError(f"Keycloak did not complete login ({result.status_code})")
    return result.headers["location"]


@contextmanager
def browser_login(context, username, password):
    with httpx.Client(verify=context, timeout=20, trust_env=False, follow_redirects=False) as http:
        start = http.get(CONTROL + "/auth/login")
        assert start.status_code in {302, 307}
        callback = login_form(http, start.headers["location"], username, password)
        assert callback.startswith(CONTROL + "/auth/callback?")
        result = http.get(callback)
        assert result.status_code in {302, 303, 307}, (
            f"Application OIDC callback refused: {result.status_code}"
        )
        assert "atomic_session" in http.cookies
        principal = http.get(CONTROL + "/api/v1/me")
        principal.raise_for_status()
        assert principal.json()["mode"] == "real" and principal.json()["dev_auth"] is False
        assert set(principal.json()["roles"]) == set(USER_ROLES[username])
        yield http, principal.json()


def oauth_tokens(
    context,
    username,
    password,
    scope="openid atomic:read atomic:request atomic:cleanup",
    wrong_verifier=False,
):
    verifier, state, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    challenge = urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    with httpx.Client(verify=context, timeout=20, trust_env=False, follow_redirects=False) as http:
        url = (
            AUTH
            + "?"
            + urlencode(
                {
                    "client_id": CODEX,
                    "redirect_uri": CALLBACK,
                    "response_type": "code",
                    "scope": scope,
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )
        callback = login_form(http, url, username, password)
        assert callback.startswith(CALLBACK + "?")
        query = parse_qs(urlsplit(callback).query)
        assert query["state"] == [state] and "code" in query
        response = http.post(
            TOKEN,
            data={
                "grant_type": "authorization_code",
                "client_id": CODEX,
                "redirect_uri": CALLBACK,
                "code": query["code"][0],
                "code_verifier": "wrong-verifier-" + verifier if wrong_verifier else verifier,
            },
        )
        if wrong_verifier:
            assert response.status_code == 400
            return None
        response.raise_for_status()
        tokens = response.json()
        jwks = jwt.PyJWKClient(ISSUER + "/protocol/openid-connect/certs", ssl_context=context)
        key = jwks.get_signing_key_from_jwt(tokens["id_token"])
        claims = jwt.decode(tokens["id_token"], key.key, algorithms=["RS256"], issuer=ISSUER, audience=CODEX)
        assert claims["nonce"] == nonce
        return tokens


def claims_for(context, token, audience):
    jwks = jwt.PyJWKClient(ISSUER + "/protocol/openid-connect/certs", ssl_context=context)
    key = jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        key.key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=audience,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )


def exchange(http, credentials, token, scope="atomic:read", audience=API, **extra):
    return http.post(
        TOKEN,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": MCP,
            "client_secret": credentials["mcp_secret"],
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": scope,
            "audience": audience,
            **extra,
        },
    )


async def verify_mcp(context, token, read_only_token):
    @asynccontextmanager
    async def connection(access_token):
        async with httpx2.AsyncClient(
            verify=context, trust_env=False, headers={"Authorization": "Bearer " + access_token}, timeout=30
        ) as http:
            async with streamable_http_client(MCP, http_client=http) as streams:
                yield streams

    async with Client(connection(token)) as client:
        tools = (await client.list_tools()).tools
        assert len(tools) == 8 and not any("approve" in tool.name for tool in tools)
        tests = (await client.call_tool("atomic_list_tests", {})).structured_content
        assert tests and tests["ok"] and tests["data"]["total"] >= 0
        actors = (await client.call_tool("atomic_list_actors", {})).structured_content
        assert actors and actors["ok"] and actors["data"]["total"] >= 0
    async with Client(connection(read_only_token)) as client:
        missing = str(uuid4())
        refused = (
            await client.call_tool(
                "atomic_request_test",
                {
                    "guid": missing,
                    "actor_id": missing,
                    "execution_profile_id": missing,
                    "reason": "Verify insufficient scope is refused before dispatch",
                    "idempotency_key": str(uuid4()),
                },
            )
        ).structured_content
        assert refused and refused["ok"] is False and refused["error"]["code"] == "insufficient_scope"
    return {
        "eight_authenticated_tools": True,
        "delegated_api_queries": True,
        "read_only_scope_enforced": True,
        "approval_tools_absent": True,
        "listed_test_count": tests["data"]["total"],
        "listed_actor_count": actors["data"]["total"],
    }


def main():
    global CONTROL, ISSUER, AUTH, TOKEN, KEYCLOAK
    os.environ.update(environment())
    CONTROL = os.environ["ATOMIC_PUBLIC_URL"]
    ISSUER = os.environ["ATOMIC_OIDC_ISSUER"]
    KEYCLOAK = ISSUER.rsplit("/realms/", 1)[0]
    AUTH = ISSUER + "/protocol/openid-connect/auth"
    TOKEN = ISSUER + "/protocol/openid-connect/token"
    context = ssl.create_default_context(cafile=str(RUNTIME / "tls/ca-bundle.pem"))
    credentials = json.loads((RUNTIME / "credentials.json").read_text())
    report: dict[str, Any] = {
        "issuer": ISSUER,
        "dashboard": CONTROL,
        "mcp": MCP,
        "certificate_validation": True,
        "approval_mode": os.environ.get("ATOMIC_APPROVAL_MODE", "catalog"),
        "roles": {},
        "atomic_execution_performed": False,
    }
    with httpx.Client(verify=context, timeout=20, trust_env=False, follow_redirects=False) as http:
        assert http.get(CONTROL + "/health").json()["mode"] == "real"
        assert http.get(CONTROL + "/api/v1/me").status_code == 401
        assert http.get(CONTROL + "/api/v1/me", headers={"X-Dev-User": "admin"}).status_code == 401
        metadata = http.get("https://localhost:19444/.well-known/oauth-protected-resource/mcp")
        metadata.raise_for_status()
        assert metadata.json()["resource"] == MCP
        denied = http.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert denied.status_code == 401
    subjects = {}
    for username, roles in USER_ROLES.items():
        with browser_login(context, username, credentials["users"][username]) as (browser, principal):
            principal = browser.get(CONTROL + "/api/v1/me").json()
            assert principal["session_expires_in"] > 86300
            if username == "atomic-viewer":
                report["browser_session"] = verify_browser_refresh(browser)
            assert principal["approval_mode"] == report["approval_mode"]
            subjects[username] = principal["subject"]
            package = browser.get(CONTROL + "/api/v1/agents/package-options")
            assert package.status_code == (200 if "administrator" in roles else 403)
            report["roles"][username] = {
                "subject": principal["subject"],
                "roles": sorted(roles),
                "browser_pkce_session": True,
                "administrator_boundary": True,
            }
            assert browser.post(CONTROL + "/auth/logout").status_code == 303
            assert browser.get(CONTROL + "/api/v1/me").status_code == 401
        print("Verified browser login, roles, access boundary and logout:", username, flush=True)
    username = "atomic-operator"
    tokens = oauth_tokens(context, username, credentials["users"][username])
    assert tokens
    incoming = claims_for(context, tokens["access_token"], MCP)
    assert incoming["sub"] == subjects[username]
    assert {"atomic:read", "atomic:request", "atomic:cleanup"} <= set(incoming["scope"].split())
    read_only = oauth_tokens(context, "atomic-viewer", credentials["users"]["atomic-viewer"])
    assert read_only
    viewer_claims = claims_for(context, read_only["access_token"], MCP)
    assert set(viewer_claims["scope"].split()) == {"openid", "atomic:read"}
    with httpx.Client(verify=context, timeout=20, trust_env=False) as http:
        delegated = exchange(http, credentials, tokens["access_token"])
        delegated.raise_for_status()
        api_token = delegated.json()["access_token"]
        outgoing = claims_for(context, api_token, API)
        assert outgoing["sub"] == incoming["sub"] and outgoing["azp"] == MCP
        assert set(outgoing["scope"].split()) <= set(incoming["scope"].split())
        me = http.get(CONTROL + "/api/v1/me", headers={"Authorization": "Bearer " + api_token})
        me.raise_for_status()
        assert me.json()["subject"] == subjects[username] and set(me.json()["roles"]) == {"viewer"}
        forbidden = http.get(
            CONTROL + "/api/v1/agents/package-options", headers={"Authorization": "Bearer " + api_token}
        )
        assert forbidden.status_code == 403
        upscope = exchange(http, credentials, read_only["access_token"], "atomic:read atomic:request")
        assert upscope.status_code in {400, 403}, "Provider allowed scope expansion"
        target = exchange(http, credentials, tokens["access_token"], audience="realm-management")
        assert target.status_code in {400, 403}, "Provider allowed an unintended audience"
        wrong_resource = http.post(
            MCP,
            headers={"Authorization": "Bearer " + api_token},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert wrong_resource.status_code == 401
    oauth_tokens(context, username, credentials["users"][username], wrong_verifier=True)
    report["oauth"] = {
        "authorization_code_pkce": True,
        "wrong_verifier_refused": True,
        "rs256_jwks_validation": True,
        "subject_preserved": True,
        "exchange_azp_preserved": True,
        "scope_expansion_refused": True,
        "viewer_write_scopes_refused": True,
        "wrong_audience_refused": True,
        "development_identity_refused": True,
        "unauthenticated_mcp_refused": True,
    }
    report["mcp_checks"] = asyncio.run(verify_mcp(context, tokens["access_token"], read_only["access_token"]))
    private_write(RUNTIME / "verification.json", json.dumps(report, indent=2).encode())
    print("Verified real HTTPS OIDC, PKCE, roles, logout, constrained token exchange and authenticated MCP.")
    print("No Atomic test or agent was executed. Report:", RUNTIME / "verification.json")


if __name__ == "__main__":
    main()
