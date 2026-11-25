import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.app import auth
from apps.api.app.auth import sessions
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import Base, BrowserSession
from apps.api.app.services.common import digest


@pytest.fixture
def browser(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = tmp_path / "signer.pem"
    signer.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    encryption = tmp_path / "browser.key"
    encryption.write_bytes(Fernet.generate_key())
    encryption.chmod(0o600)
    settings = Settings(
        mode="real",
        database_url=f"sqlite:///{tmp_path}/browser.db",
        signing_key_file=str(signer),
        oidc_issuer="https://id.example.test/realms/atomic-control",
        oidc_jwks_url="https://id.example.test/certs",
        oidc_client_id="atomic-control-browser",
        oidc_client_secret="test-only-client-secret",
        public_url="https://control.test",
        browser_session_key_file=str(encryption),
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    state = {
        "app": app,
        "settings": settings,
        "clock": time.time(),
        "nonce": "",
        "refreshes": 0,
        "refresh_status": 200,
        "roles": ["viewer", "operator"],
        "subject": "human",
        "revocations": 0,
        "revocation_status": 200,
        "access_change": {},
        "id_change": {},
        "refresh_change": {},
        "no_refresh": False,
        "outage": False,
    }
    monkeypatch.setattr(sessions, "time", SimpleNamespace(time=lambda: state["clock"]))
    monkeypatch.setattr(
        auth,
        "jwks_client",
        lambda _: SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key.public_key())),
    )

    def token(audience=None, **changes):
        return jwt.encode(
            {
                "iss": settings.oidc_issuer,
                "aud": audience or settings.oidc_audience,
                "sub": "human",
                "preferred_username": "fixture.operator",
                "iat": int(time.time()) - 1,
                "exp": int(state["clock"]) + 300,
                "azp": settings.oidc_client_id,
                "scope": "openid profile",
                "roles": ["viewer", "operator"],
                **changes,
            },
            key,
            algorithm="RS256",
        )

    state["token"] = token

    def get(url, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "issuer": settings.oidc_issuer,
                "authorization_endpoint": "https://id.example.test/auth",
                "token_endpoint": "https://id.example.test/token",
                "revocation_endpoint": "https://id.example.test/revoke",
            },
        )

    def post(url, data, **kwargs):
        if url.endswith("/revoke"):
            state["revocations"] += 1
            return httpx.Response(state["revocation_status"], request=httpx.Request("POST", url), json={})
        if data["grant_type"] == "refresh_token":
            state["refreshes"] += 1
            if state["outage"]:
                raise httpx.ConnectError("test outage")
            return httpx.Response(
                state["refresh_status"],
                request=httpx.Request("POST", url),
                json={
                    "access_token": token(
                        sub=state["subject"], roles=state["roles"], **state["refresh_change"]
                    ),
                    "refresh_token": f"rotated-refresh-{state['refreshes']}",
                    "expires_in": 300,
                },
            )
        value = {
            "access_token": token(**state["access_change"]),
            "id_token": token(settings.oidc_client_id, **{"nonce": state["nonce"], **state["id_change"]}),
            "refresh_token": "private-test-refresh-token",
            "expires_in": 300,
            "refresh_expires_in": 86400,
        }
        if state["no_refresh"]:
            value.pop("refresh_token")
        return httpx.Response(200, request=httpx.Request("POST", url), json=value)

    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr(httpx, "post", post)
    state["client"] = TestClient(app, base_url=settings.public_url)
    return state


def start(s):
    response = s["client"].get("/auth/login", follow_redirects=False)
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"] and "code_verifier" not in query
    s["nonce"] = query["nonce"][0]
    return query["state"][0]


def login(s):
    response = s["client"].get(
        "/auth/callback",
        params={"code": "test-authorization-code", "state": start(s)},
        follow_redirects=False,
    )
    assert response.status_code == 307, response.text
    return response


def record(s):
    with s["app"].state.sessions() as db:
        return db.scalar(select(BrowserSession))


def test_browser_cookie_is_24_hours_and_tokens_are_encrypted_server_side(browser):
    s = browser
    response = login(s)
    cookie = response.headers["set-cookie"]
    assert (
        "Max-Age=86400" in cookie
        and "HttpOnly" in cookie
        and "Secure" in cookie
        and "SameSite=strict" in cookie
    )
    session_id = s["client"].cookies["atomic_session"]
    item = record(s)
    assert item.id == digest(session_id) and item.id != session_id
    assert item.expires_at - item.created_at == 86400
    assert (
        "private-test-refresh-token" not in item.encrypted_tokens
        and "access_token" not in item.encrypted_tokens
    )
    me = s["client"].get("/api/v1/me")
    assert me.status_code == 200 and me.json()["session_expires_in"] > 86390
    assert me.json()["session_expires_at"] == item.expires_at and s["refreshes"] == 0
    assert me.json()["username"] == "fixture.operator" and me.json()["subject"] == "human"


def test_expired_access_token_refreshes_once_for_parallel_requests_and_does_not_extend_deadline(browser):
    s = browser
    login(s)
    original = record(s)
    s["clock"] += 600
    paths = ["me", "actors", "tests", "runs", "audit", "approvals"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda path: s["client"].get("/api/v1/" + path), paths))
    assert all(r.status_code == 200 for r in responses), [(r.status_code, r.text) for r in responses]
    assert s["refreshes"] == 1 and record(s).expires_at == original.expires_at
    value = s["app"].state.browser_sessions.decrypt(record(s))
    assert value["refresh_token"] == "rotated-refresh-1"
    assert s["client"].get("/api/v1/me").json()["roles"] == ["operator", "viewer"]
    assert s["client"].get("/api/v1/me").json()["username"] == "fixture.operator"


def test_absolute_24_hour_expiry_clears_cookie_and_never_refreshes(browser):
    s = browser
    login(s)
    s["clock"] += 86401
    response = s["client"].get("/api/v1/me")
    assert response.status_code == 401 and "Max-Age=0" in response.headers["set-cookie"]
    assert record(s) is None and s["refreshes"] == 0


@pytest.mark.parametrize(
    "change", ["rejected", "subject", "audience", "issuer", "scope", "no_viewer", "expired"]
)
def test_revoked_or_invalid_replacement_token_closes_session(browser, change):
    s = browser
    login(s)
    s["clock"] += 600
    if change == "rejected":
        s["refresh_status"] = 400
    elif change == "subject":
        s["subject"] = "another-person"
    elif change == "audience":
        s["refresh_change"] = {"aud": "wrong-api"}
    elif change == "issuer":
        s["refresh_change"] = {"iss": "https://wrong-issuer.test"}
    elif change == "scope":
        s["refresh_change"] = {"scope": "openid atomic:request"}
    elif change == "no_viewer":
        s["roles"] = []
    else:
        s["refresh_change"] = {"exp": int(time.time()) - 1}
    response = s["client"].get("/api/v1/me")
    assert response.status_code == 401 and record(s) is None


def test_role_changes_take_effect_after_refresh_without_logging_out_viewer(browser):
    s = browser
    login(s)
    s["clock"] += 600
    s["roles"] = ["viewer"]
    response = s["client"].get("/api/v1/me")
    assert response.status_code == 200 and response.json()["roles"] == ["viewer"]
    assert record(s) is not None


@pytest.mark.parametrize("outage", [True, False])
def test_provider_outage_preserves_session_for_retry_and_fails_closed(browser, outage):
    s = browser
    login(s)
    deadline = record(s).expires_at
    s["clock"] += 600
    s["outage"] = outage
    s["refresh_status"] = 503 if not outage else 200
    response = s["client"].get("/api/v1/me")
    assert response.status_code == 503 and record(s).expires_at == deadline
    assert "set-cookie" not in response.headers
    s["outage"] = False
    s["refresh_status"] = 200
    assert s["client"].get("/api/v1/me").status_code == 200


@pytest.mark.parametrize("revocation_status", [200, 503])
def test_logout_is_durable_and_replayed_cookie_stays_invalid(browser, revocation_status):
    s = browser
    login(s)
    cookie = s["client"].cookies["atomic_session"]
    s["revocation_status"] = revocation_status
    assert s["client"].post("/auth/logout", follow_redirects=False).status_code == 303
    assert record(s) is None and s["revocations"] == 1
    response = s["client"].get("/api/v1/me", headers={"Cookie": "atomic_session=" + cookie})
    assert response.status_code == 401


def test_browser_session_survives_api_restart_with_same_protected_key(browser):
    s = browser
    login(s)
    cookie = s["client"].cookies["atomic_session"]
    restarted = create_app(s["settings"])
    response = TestClient(restarted, base_url=s["settings"].public_url).get(
        "/api/v1/me", headers={"Cookie": "atomic_session=" + cookie}
    )
    assert response.status_code == 200 and response.json()["subject"] == "human"


def test_corrupt_encrypted_session_is_rejected_and_removed(browser):
    s = browser
    login(s)
    with s["app"].state.sessions() as db, db.begin():
        db.get(BrowserSession, record(s).id).encrypted_tokens = "tampered"
    assert s["client"].get("/api/v1/me").status_code == 401 and record(s) is None


def test_expired_bearer_token_does_not_use_cookie_refresh_or_extend_session(browser):
    s = browser
    login(s)
    response = s["client"].get(
        "/api/v1/me", headers={"Authorization": "Bearer " + s["token"](exp=int(time.time()) - 1)}
    )
    assert response.status_code == 401 and s["refreshes"] == 0 and record(s) is not None


@pytest.mark.parametrize("change", ["nonce", "state", "subject", "no_viewer", "no_refresh"])
def test_callback_rejects_invalid_login_binding_or_missing_refresh(browser, change):
    s = browser
    state = start(s)
    if change == "nonce":
        s["id_change"] = {"nonce": "wrong"}
    elif change == "state":
        state = "wrong-state"
    elif change == "subject":
        s["access_change"] = {"sub": "another-person"}
    elif change == "no_viewer":
        s["access_change"] = {"roles": []}
    else:
        s["no_refresh"] = True
    response = s["client"].get(
        "/auth/callback", params={"code": "code", "state": state}, follow_redirects=False
    )
    assert response.status_code == (503 if change == "no_refresh" else 401), response.text
    assert record(s) is None


def test_session_encryption_key_requires_private_permissions(browser):
    s = browser
    from pathlib import Path

    Path(s["settings"].browser_session_key_file).chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        create_app(s["settings"])
