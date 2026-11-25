"""Durable desired-state reconciliation; never carries commands or credentials."""

import time

from sqlalchemy import select

from apps.agent.profile_config import FIELDS, fingerprint, payload

from ..errors import fail
from ..models import Audit, Lease, Profile, ProfileSync, Run
from .actor_status import require_current_actor
from .common import audit, transition


def latest(db, actor):
    return db.scalar(
        select(ProfileSync)
        .where(ProfileSync.actor_id == actor.id)
        .order_by(ProfileSync.generation.desc())
        .limit(1)
    )


def desired(db, actor):
    return payload(
        {
            "actor_id": actor.id,
            "hostname": actor.hostname,
            "os": actor.os,
            "profiles": [
                {k: getattr(p, k) for k in FIELDS}
                for p in db.scalars(select(Profile).where(Profile.actor_id == actor.id))
            ],
        }
    )


def queue(db, actor, identity, retry=False):
    require_current_actor(actor)
    value = desired(db, actor)
    hashed = fingerprint(value)
    previous = latest(db, actor)
    if (
        previous
        and previous.payload_hash == hashed
        and (
            not retry
            or (previous.status in {"pending", "applying"} and time.time() - previous.updated_at < 180)
        )
    ):
        return previous
    if previous and previous.status in {"pending", "applying"}:
        previous.status, previous.updated_at = "superseded", time.time()
    item = ProfileSync(
        actor_id=actor.id,
        generation=previous.generation + 1 if previous else 1,
        payload=value,
        payload_hash=hashed,
        requested_by=identity,
    )
    db.add(item)
    db.flush()
    audit(db, identity, "profile_sync.requested", actor.id, generation=item.generation, payload_hash=hashed)
    return item


def reconcile(db, actor, check_drift=False):
    if actor.os in {"linux", "windows"} and not actor.simulated and actor.profile_sync_protocol == 1:
        item = queue(db, actor, "system:profile-reconciliation")
        if (
            check_drift
            and item.status in {"applied", "validation_failed"}
            and actor.profile_config_hash != item.payload_hash
        ):
            queue(db, actor, "system:profile-drift", retry=True)


def view(db, actor):
    item = latest(db, actor)
    return {
        "supported": actor.os in {"linux", "windows"} and not actor.simulated,
        "protocol": actor.profile_sync_protocol,
        "status": item.status if item else "not_configured",
        "generation": item.generation if item else 0,
        "updated_at": item.updated_at if item else None,
        "results": item.results if item else {},
        "error": item.error if item else "",
    }


def blocks_claim(db, actor):
    if actor.profile_sync_protocol != 1:
        return False
    item = latest(db, actor)
    return bool(item and item.status in {"pending", "applying", "failed"})


def delete_profile(db, actor, profile_id, identity):
    """Remove registration, cancel waiting requests and retain immutable evidence."""
    require_current_actor(actor)
    profile = db.get(Profile, str(profile_id))
    if profile is None:
        receipt = db.scalar(
            select(Audit).where(Audit.action == "profile.deleted", Audit.resource == str(profile_id))
        )
        if receipt and receipt.details.get("actor_id") == actor.id:
            return {
                "id": str(profile_id),
                "deleted": True,
                "cancelled_requests": receipt.details["cancelled_requests"],
            }
        fail("not_found", "Execution profile does not exist", 404)
    if profile.actor_id != actor.id:
        fail("not_found", "Execution profile does not exist on this actor", 404)
    from .catalog_deployments import applying

    sync = latest(db, actor)
    uncertain = db.scalar(
        select(Run.id)
        .where(
            Run.actor_id == actor.id,
            (Run.status.in_(["claimed", "running"]))
            | ((Run.status == "inconclusive") & Run.reconciled.is_(False)),
        )
        .limit(1)
    )
    if db.get(Lease, actor.id) or uncertain or applying(db, actor) or (sync and sync.status == "applying"):
        fail(
            "actor_busy",
            "Finish active work, reconcile uncertain outcomes, or finish the current profile update before deleting a profile",
            409,
        )
    waiting = db.scalars(
        select(Run).where(
            Run.actor_id == actor.id,
            Run.profile_id == profile.id,
            Run.status.in_(["pending_approval", "queued", "preparing"]),
        )
    ).all()
    for run in waiting:
        run.cancel_requested = True
        transition(db, run, "cancelled", identity)
    details = {k: getattr(profile, k) for k in FIELDS}
    db.delete(profile)
    db.flush()
    # Also queue removals for older agents. Their next capability heartbeat can
    # deliver the current desired state after the one-time runtime update.
    queue(db, actor, identity)
    audit(
        db,
        identity,
        "profile.deleted",
        str(profile_id),
        actor_id=actor.id,
        profile=details,
        cancelled_requests=len(waiting),
    )
    return {"id": str(profile_id), "deleted": True, "cancelled_requests": len(waiting)}
