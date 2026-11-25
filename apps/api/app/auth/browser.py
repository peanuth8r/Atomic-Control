"""OIDC authorization code + PKCE. Tokens stay server-side; browser gets HttpOnly session."""

import hashlib
import secrets
import time
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from ..errors import fail
from . import verify_oidc
from .sessions import SessionUnavailable, browser_claims

router = APIRouter(prefix="/auth")


def prune(store):
    now = time.time()
    for key in list(store):
        if store[key]["expires"] <= now:
            del store[key]


@router.get("/config")
def config(request: Request):
    s = request.app.state.settings
    return {"dev_auth": s.dev_auth, "mode": s.mode, "oidc_enabled": bool(s.oidc_issuer)}


@router.get("/login")
def login(request: Request):
    s = request.app.state.settings
    if not s.oidc_issuer or not s.oidc_client_id:
        fail("oidc_not_configured", "Configure the OIDC client", 503)
    discovery = (
        httpx.get(s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=10)
        .raise_for_status()
        .json()
    )
    if discovery.get("issuer") != s.oidc_issuer or any(
        not discovery[k].startswith("https://") for k in ["authorization_endpoint", "token_endpoint"]
    ):
        fail("invalid_provider", "Invalid OIDC discovery metadata", 503)
    state, verifier, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    prune(request.app.state.oidc_pending)
    request.app.state.oidc_pending[state] = {
        "verifier": verifier,
        "nonce": nonce,
        "token_endpoint": discovery["token_endpoint"],
        "revocation_endpoint": discovery.get("revocation_endpoint")
        if discovery.get("revocation_endpoint", "").startswith("https://")
        else None,
        "expires": time.time() + 300,
    }
    challenge = urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = {
        "client_id": s.oidc_client_id,
        "redirect_uri": s.public_url + "/auth/callback",
        "response_type": "code",
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "audience": s.oidc_audience,
    }
    response = RedirectResponse(discovery["authorization_endpoint"] + "?" + urlencode(params))
    response.set_cookie("atomic_login", state, httponly=True, secure=True, samesite="lax", max_age=300)
    return response


@router.get("/callback")
def callback(request: Request, code: str, state: str):
    s = request.app.state.settings
    pending = request.app.state.oidc_pending.pop(state, None)
    if (
        not pending
        or pending["expires"] <= time.time()
        or not secrets.compare_digest(state, request.cookies.get("atomic_login", ""))
    ):
        fail("invalid_state", "Login state expired or mismatched", 401)
    tokens = (
        httpx.post(
            pending["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": s.public_url + "/auth/callback",
                "client_id": s.oidc_client_id,
                "client_secret": s.oidc_client_secret,
                "code_verifier": pending["verifier"],
            },
            timeout=10,
        )
        .raise_for_status()
        .json()
    )
    try:
        identity = verify_oidc(tokens["id_token"], s, s.oidc_client_id)
        claims = browser_claims(tokens["access_token"], s)
    except (jwt.PyJWTError, KeyError, ValueError):
        fail("invalid_token", "SSO identity or dashboard authorization could not be verified", 401)
    if identity.get("nonce") != pending["nonce"]:
        fail("invalid_nonce", "OIDC nonce mismatch", 401)
    if claims["sub"] != identity["sub"]:
        fail("identity_mismatch", "OIDC identity and access token subjects differ", 401)
    try:
        session_id = request.app.state.browser_sessions.create(
            tokens, claims, pending["token_endpoint"], pending.get("revocation_endpoint")
        )
    except SessionUnavailable:
        fail(
            "session_not_configured", "Configure browser session encryption and provider refresh tokens", 503
        )
    response = RedirectResponse("/")
    response.set_cookie(
        "atomic_session",
        session_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=s.browser_session_seconds,
    )
    response.delete_cookie("atomic_login")
    return response


@router.post("/logout")
def logout(request: Request):
    request.app.state.browser_sessions.logout(request.cookies.get("atomic_session", ""))
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("atomic_session")
    return response
