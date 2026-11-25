"""Opaque 24-hour cookies; encrypted tokens, serialized refresh and durable logout."""

import json
import os
import secrets
import stat
import time
from pathlib import Path

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select, text

from ..models import BrowserSession
from ..services.common import digest
from . import verify_oidc


class SessionUnavailable(Exception):
    pass


def browser_claims(token, settings, subject=None):
    claims = verify_oidc(token, settings)
    if (subject is not None and claims["sub"] != subject) or "viewer" not in claims.get("roles", []):
        raise jwt.InvalidTokenError("Browser subject or authorization changed")
    if claims.get("azp", settings.oidc_client_id) != settings.oidc_client_id or any(
        scope.startswith("atomic:") for scope in claims.get("scope", "").split()
    ):
        raise jwt.InvalidTokenError("Delegated tokens cannot create browser sessions")
    return claims


class BrowserSessions:
    def __init__(self, sessions, settings):
        self.sessions, self.settings = sessions, settings
        self.cipher = None
        if settings.browser_session_key_file:
            path = Path(settings.browser_session_key_file)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Browser session key must be an owner-only regular file")
            self.cipher = Fernet(path.read_bytes().strip())

    def encrypt(self, value):
        if not self.cipher:
            raise SessionUnavailable("Configure a protected browser session encryption key")
        return self.cipher.encrypt(json.dumps(value).encode()).decode()

    def decrypt(self, item):
        if not self.cipher:
            raise SessionUnavailable("Browser sessions are not configured")
        return json.loads(self.cipher.decrypt(item.encrypted_tokens.encode()))

    def begin(self, db):
        if db.bind.dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))

    def create(self, tokens, claims, endpoint, revocation_endpoint=None):
        if not tokens.get("refresh_token"):
            raise SessionUnavailable("The identity provider must issue a browser refresh token")
        now, session_id = time.time(), secrets.token_urlsafe(48)
        expires = now + self.settings.browser_session_seconds
        value = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_endpoint": endpoint,
            "revocation_endpoint": revocation_endpoint,
        }
        encrypted = self.encrypt(value)
        with self.sessions() as db:
            self.begin(db)
            db.execute(delete(BrowserSession).where(BrowserSession.expires_at <= now))
            db.add(
                BrowserSession(
                    id=digest(session_id),
                    subject=claims["sub"],
                    encrypted_tokens=encrypted,
                    created_at=now,
                    expires_at=expires,
                    access_expires_at=claims["exp"],
                )
            )
            db.commit()
        return session_id

    def read_valid(self, item, value):
        claims = browser_claims(value["access_token"], self.settings, item.subject)
        return {"token": value["access_token"], "claims": claims, "expires": item.expires_at}

    def resolve(self, session_id):
        key = digest(session_id)
        with self.sessions() as db:
            item = db.get(BrowserSession, key)
            if not item:
                return None
            try:
                value = self.decrypt(item)
                if item.expires_at > time.time() and item.access_expires_at > time.time() + 30:
                    return self.read_valid(item, value)
            except jwt.ExpiredSignatureError:
                pass  # Refresh a short-lived access token, never extend the session deadline.
            except jwt.PyJWKClientConnectionError:
                raise SessionUnavailable("The identity provider is temporarily unavailable") from None
            except (InvalidToken, ValueError, KeyError, jwt.PyJWTError):
                self.remove(session_id)
                return None
        # Refresh under one durable lock. Other processes reread the rotated token.
        with self.sessions() as db:
            self.begin(db)
            item = db.scalar(select(BrowserSession).where(BrowserSession.id == key).with_for_update())
            if not item:
                return None
            if item.expires_at <= time.time():
                db.delete(item)
                db.commit()
                return None
            try:
                value = self.decrypt(item)
                if item.access_expires_at > time.time() + 30:
                    return self.read_valid(item, value)
                response = httpx.post(
                    value["token_endpoint"],
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": value["refresh_token"],
                        "client_id": self.settings.oidc_client_id,
                        "client_secret": self.settings.oidc_client_secret,
                    },
                    timeout=10,
                    follow_redirects=False,
                )
                if response.status_code in {400, 401, 403}:
                    db.delete(item)
                    db.commit()
                    return None
                response.raise_for_status()
                tokens = response.json()
                claims = browser_claims(tokens["access_token"], self.settings, item.subject)
                if claims["exp"] <= time.time() or item.expires_at <= time.time():
                    raise jwt.InvalidTokenError("Session or replacement token expired")
                value["access_token"] = tokens["access_token"]
                value["refresh_token"] = tokens.get("refresh_token") or value["refresh_token"]
                item.encrypted_tokens, item.access_expires_at = self.encrypt(value), claims["exp"]
                db.commit()
                return self.read_valid(item, value)
            except httpx.HTTPError:
                raise SessionUnavailable("The identity provider is temporarily unavailable") from None
            except jwt.PyJWKClientConnectionError:
                raise SessionUnavailable("The identity provider is temporarily unavailable") from None
            except (InvalidToken, ValueError, KeyError, jwt.PyJWTError):
                db.delete(item)
                db.commit()
                return None

    def remove(self, session_id):
        value = None
        with self.sessions() as db:
            self.begin(db)
            item = db.scalar(
                select(BrowserSession).where(BrowserSession.id == digest(session_id)).with_for_update()
            )
            if item:
                try:
                    value = self.decrypt(item)
                except (InvalidToken, ValueError, KeyError, SessionUnavailable):
                    pass
                db.delete(item)
            db.commit()
        return value

    def logout(self, session_id):
        value = self.remove(session_id)
        if value and value.get("revocation_endpoint"):
            try:
                httpx.post(
                    value["revocation_endpoint"],
                    data={
                        "token": value["refresh_token"],
                        "token_type_hint": "refresh_token",
                        "client_id": self.settings.oidc_client_id,
                        "client_secret": self.settings.oidc_client_secret,
                    },
                    timeout=5,
                    follow_redirects=False,
                ).raise_for_status()
            except httpx.HTTPError:
                pass  # Local logout is durable even when the provider is unavailable.
