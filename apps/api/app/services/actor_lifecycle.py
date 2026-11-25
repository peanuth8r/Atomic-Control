"""Permanently remove actor enrollment state while preserving immutable execution evidence."""

import time

from sqlalchemy import delete, func, or_, select

from ..errors import fail
from ..jobs.engine import TERMINAL
from ..models import (
    Audit,
    CatalogDeployment,
    Credential,
    Enrollment,
    Lease,
    Profile,
    ProfileSync,
    Run,
    RunBatch,
)
from .catalog_deployments import applying as catalog_applying
from .common import audit, transition


def deletion_receipt(db, actor_id):
    event = db.scalar(select(Audit).where(Audit.action == "actor.deleted", Audit.resource == str(actor_id)))
    if event is None:
        return None
    return {
        "id": event.resource,
        "hostname": event.details["hostname"],
        "deleted": True,
        "deleted_at": event.timestamp,
        "deleted_by": event.identity,
        "reason": event.details["reason"],
    }


def retire(db, actor, identity, reason):
    # The caller locks the actor first, matching agent authentication and dispatch.
    unresolved = db.scalar(
        select(Run.id)
        .where(
            Run.actor_id == actor.id,
            or_(
                Run.status.not_in(TERMINAL | {"pending_approval", "queued", "preparing"}),
                (Run.status == "inconclusive") & Run.reconciled.is_(False),
            ),
        )
        .limit(1)
    )
    if db.get(Lease, actor.id) is not None or unresolved or catalog_applying(db, actor):
        fail(
            "actor_busy",
            "Finish active executions/catalog installation and reconcile uncertain outcomes before retiring this actor",
            409,
        )
    now = time.time()
    counts = {
        "credentials_revoked": 0,
        "enrollment_tokens_invalidated": 0,
        "runs_cancelled": 0,
        "profile_syncs_cancelled": 0,
        "catalog_deployments_cancelled": 0,
    }
    for batch in db.scalars(
        select(RunBatch).where(RunBatch.actor_id == actor.id, RunBatch.cancelled.is_(False))
    ):
        if db.scalar(
            select(Run.id)
            .where(Run.batch_id == batch.id, Run.status.in_(["pending_approval", "queued", "preparing"]))
            .limit(1)
        ):
            batch.cancelled, batch.paused, batch.pause_reason = True, False, "actor_deleted"
            audit(db, identity, "queue.cancelled", batch.id, reason="actor_deleted")
    for credential in db.scalars(
        select(Credential).where(Credential.actor_id == actor.id, Credential.revoked.is_(False))
    ):
        credential.revoked = True
        credential.expires_at = min(credential.expires_at, now)
        counts["credentials_revoked"] += 1
    # Include legacy hostname-bound tokens, even if their actor_id is null.
    for token in db.scalars(
        select(Enrollment).where(
            or_(Enrollment.actor_id == actor.id, func.lower(Enrollment.hostname) == actor.hostname.lower()),
            Enrollment.used.is_(False),
        )
    ):
        token.used = True
        token.expires_at = min(token.expires_at, now)
        counts["enrollment_tokens_invalidated"] += 1
    for run in db.scalars(
        select(Run).where(
            Run.actor_id == actor.id, Run.status.in_(["pending_approval", "queued", "preparing"])
        )
    ):
        run.cancel_requested = True
        transition(db, run, "cancelled", identity)
        counts["runs_cancelled"] += 1
    for sync in db.scalars(
        select(ProfileSync).where(
            ProfileSync.actor_id == actor.id, ProfileSync.status.in_(["pending", "applying"])
        )
    ):
        sync.status, sync.error, sync.updated_at = "cancelled", "actor_retired", now
        counts["profile_syncs_cancelled"] += 1
    for deployment in db.scalars(
        select(CatalogDeployment).where(
            CatalogDeployment.actor_id == actor.id, CatalogDeployment.status == "pending"
        )
    ):
        deployment.status, deployment.error, deployment.updated_at = "cancelled", "actor_retired", now
        counts["catalog_deployments_cancelled"] += 1
    actor_id, hostname = actor.id, actor.hostname
    db.flush()
    # Run actor/profile IDs are historical values, and their signed snapshots remain untouched.
    # Delete all transport and operational rows so nothing can transfer to a replacement actor.
    models: list[
        type[Credential] | type[Enrollment] | type[ProfileSync] | type[CatalogDeployment] | type[Profile]
    ] = [Credential, Enrollment, ProfileSync, CatalogDeployment, Profile]
    for model in models:
        predicate = model.actor_id == actor_id
        if model is Enrollment:
            predicate = or_(predicate, func.lower(Enrollment.hostname) == hostname.lower())
        removed = db.execute(delete(model).where(predicate))
        counts[model.__tablename__ + "_deleted"] = removed.rowcount
    db.delete(actor)
    audit(db, identity, "actor.deleted", actor_id, hostname=hostname, reason=reason, **counts)
    db.flush()
    return deletion_receipt(db, actor_id)
