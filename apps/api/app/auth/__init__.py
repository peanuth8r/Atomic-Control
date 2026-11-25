from dataclasses import dataclass
from functools import lru_cache

import jwt
from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session
from ..errors import fail
from ..models import Actor, Credential
from ..services.actor_status import require_current_actor
from ..services.common import digest


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    scopes: frozenset[str]
    mcp: bool = False
    username: str = ""

    def require(self, role: str):
        if self.mcp and role in {"approver", "privileged_approver", "administrator"}:
            fail("forbidden", "MCP identities cannot approve or administer", 403)
        if role not in self.roles:
            fail("forbidden", f"Permission required: {role}", 403)


@lru_cache(maxsize=16)
def jwks_client(url: str):
    return jwt.PyJWKClient(url, cache_keys=True)


def verify_oidc(token: str, settings, audience: str | None = None) -> dict:
    key = jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        key.key,
        algorithms=["RS256"],
        audience=audience or settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"require": ["exp", "iss", "aud", "sub", "iat"]},
    )


def bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header and request.cookies.get("atomic_session"):
        item = getattr(request.state, "browser_session", None)
        if getattr(request.state, "browser_session_unavailable", False):
            fail("session_unavailable", "Sign-in verification is temporarily unavailable. Please retry", 503)
        if item:
            request.state.browser_session_expires_at = item["expires"]
            return item["token"]
    if not header.startswith("Bearer "):
        fail("unauthenticated", "Bearer authentication required", 401)
    return header[7:]


def human(request: Request) -> Principal:
    settings = request.app.state.settings
    if not settings.oidc_issuer:
        fail("auth_not_configured", "Configure OIDC authentication", 401)
    try:
        token = bearer(request)
        item = getattr(request.state, "browser_session", None)
        claims = (
            item["claims"]
            if item and not request.headers.get("authorization")
            else verify_oidc(token, settings)
        )
        from ..services.user_access import require_current

        require_current(request.app.state.sessions, claims)
        scopes = frozenset(claims.get("scope", "").split())
        # A token with MCP scopes is always restricted, regardless of its role claims.
        mcp = any(x.startswith("atomic:") for x in scopes) or claims.get("azp", "") in [
            value for value in settings.mcp_client_ids.split(",") if value
        ]
        roles = set(claims.get("roles", []))
        if mcp:
            roles = {"viewer"} if "atomic:read" in scopes else set()
            if "atomic:request" in scopes or "atomic:cleanup" in scopes:
                roles.add("operator")
        request.state.identity = claims["sub"]
        username = claims.get("preferred_username")
        username = username.strip() if isinstance(username, str) else ""
        return Principal(claims["sub"], frozenset(roles), scopes, mcp, username)
    except jwt.PyJWTError:
        fail("invalid_token", "Invalid or expired token", 401)


def viewer(p: Principal = Depends(human)) -> Principal:
    p.require("viewer")
    return p


def agent(request: Request, db: Session = Depends(session)) -> Actor:
    import time

    credential = db.scalar(
        select(Credential).where(
            Credential.digest == digest(bearer(request)),
            Credential.revoked.is_(False),
            Credential.expires_at > time.time(),
        )
    )
    if not credential:
        fail("invalid_agent", "Invalid or expired agent credential", 401)
    actor = db.get(Actor, credential.actor_id, with_for_update=True)
    if actor:
        require_current_actor(actor)
    if not actor or not actor.enabled:
        fail("actor_disabled", "Actor is disabled", 403)
    if actor.simulated:
        fail("mode_mismatch", "Legacy fixture actors cannot authenticate", 403)
    request.state.identity = "agent:" + actor.id
    return actor
