"""Durable access revocation and short, cross-process account-update leases."""

import time
from uuid import uuid4

import jwt
from sqlalchemy import delete, text

from ..errors import fail
from ..models import BrowserSession, UserAccessState, UserRoleLease
from .common import audit


def require_current(sessions, claims):
    with sessions() as db:
        state = db.get(UserAccessState, claims["sub"])
        if state and (state.blocked or claims.get("iat", 0) < state.invalid_before):
            raise jwt.InvalidTokenError("Account access changed; sign in again")


def begin(db):
    if db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))


def acquire(sessions):
    owner = str(uuid4())
    with sessions() as db:
        begin(db)
        lease = db.get(UserRoleLease, 1, with_for_update=True)
        if not lease:
            lease = UserRoleLease(id=1, owner="", expires_at=0)
            db.add(lease)
        if lease.expires_at > time.time():
            fail("user_roles_busy", "Another account update is in progress. Retry shortly", 409)
        lease.owner, lease.expires_at = owner, time.time() + 180
        db.commit()
    return owner


def release(sessions, owner):
    with sessions() as db:
        begin(db)
        lease = db.get(UserRoleLease, 1, with_for_update=True)
        if lease and lease.owner == owner:
            lease.owner, lease.expires_at = "", 0
        db.commit()


def hold(
    sessions, owner, subject, identity, before, after, *, action="user.roles_change_requested", **details
):
    with sessions() as db:
        begin(db)
        lease = db.get(UserRoleLease, 1, with_for_update=True)
        if not lease or lease.owner != owner or lease.expires_at <= time.time():
            fail("user_roles_busy", "Role update ownership expired; refresh before retrying", 409)
        state = db.get(UserAccessState, subject)
        if not state:
            state = UserAccessState(subject=subject, invalid_before=0, blocked=False, updated_by=identity)
            db.add(state)
        state.blocked, state.invalid_before = True, max(state.invalid_before, int(time.time()) + 1)
        state.updated_at, state.updated_by = time.time(), identity
        db.execute(delete(BrowserSession).where(BrowserSession.subject == subject))
        audit(db, identity, action, subject, before=before, after=after, **details)
        db.commit()


def finish(sessions, owner, subject, identity, before, after, cutoff):
    with sessions() as db:
        begin(db)
        lease = db.get(UserRoleLease, 1, with_for_update=True)
        if not lease or lease.owner != owner or lease.expires_at <= time.time():
            fail("user_roles_busy", "Role update ownership expired; refresh before retrying", 409)
        state = db.get(UserAccessState, subject, with_for_update=True)
        state.blocked, state.invalid_before = False, max(state.invalid_before, cutoff)
        state.updated_at, state.updated_by = time.time(), identity
        db.execute(delete(BrowserSession).where(BrowserSession.subject == subject))
        audit(db, identity, "user.roles_updated", subject, before=before, after=after, sessions_revoked=True)
        db.commit()
