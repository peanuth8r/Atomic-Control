"""Shared execution request path for single tests and actor batches."""

import time

from sqlalchemy import select

from ..auth.policy import authorize_execution
from ..errors import fail
from ..jobs.engine import eligibility, snapshot
from ..models import Actor, AtomicTest, Cleanup, Profile, Run, RunApproval
from .common import audit, fingerprint, transition


def create_run(db, settings, p, data, key, action=None, parent=None, batch_id=None):
    p.require("operator")
    requested_action = action or data.action
    if p.mcp and ("atomic:cleanup" if requested_action == "cleanup" else "atomic:request") not in p.scopes:
        fail("insufficient_scope", "Caller lacks action scope", 403)
    if not key or len(key) > 128:
        fail("idempotency_required", "A 1–128 character Idempotency-Key is required", 422)
    body_hash = fingerprint({**data.model_dump(mode="json"), "action": requested_action, "parent_id": parent})
    existing = db.scalar(select(Run).where(Run.requested_by == p.subject, Run.idempotency_key == key))
    if existing:
        if existing.request_hash != body_hash:
            fail("idempotency_conflict", "Key already used for a different request")
        return existing
    actor = db.get(Actor, str(data.actor_id), with_for_update=True)
    existing = db.scalar(select(Run).where(Run.requested_by == p.subject, Run.idempotency_key == key))
    if existing:
        if existing.request_hash != body_hash:
            fail("idempotency_conflict", "Key already used for a different request")
        return existing
    test = db.get(AtomicTest, str(data.atomic_guid))
    profile = db.get(Profile, str(data.execution_profile_id))
    historical_review = None
    if parent and requested_action == "cleanup" and db.get(Run, parent).snapshot.get("file_plan"):
        from .file_plans import historical_context

        test, historical_review = historical_context(db, db.get(Run, parent))
    elif parent and requested_action == "cleanup" and db.get(Run, parent).snapshot.get("artifact"):
        from .test_artifacts import historical_context

        test, historical_review = historical_context(db, db.get(Run, parent))
    review = eligibility(db, test, actor, profile, settings, historical_review)
    authorize_execution(settings, p, actor, profile, test, review.risk_level, requested_action)
    snap = snapshot(test, actor, profile, requested_action, data.timeout_seconds, review)
    actor.queue_sequence += 1
    run = Run(
        batch_id=batch_id,
        queue_position=actor.queue_sequence,
        guid=test.guid,
        actor_id=actor.id,
        profile_id=profile.id,
        reason=data.reason,
        requested_by=p.subject,
        idempotency_key=key,
        request_hash=body_hash,
        action=requested_action,
        snapshot=snap,
        snapshot_hash=fingerprint(snap),
        parent_id=parent,
    )
    db.add(run)
    db.flush()
    if parent:
        db.add(Cleanup(id=run.id, parent_id=parent))
        db.flush()
    if settings.approval_mode == "catalog":
        db.add(
            RunApproval(
                run_id=run.id,
                approved_by=review.approved_by,
                authorization_source="catalog",
                snapshot_hash=run.snapshot_hash,
                expires_at=time.time() + settings.approval_seconds,
                decision="approved",
            )
        )
        transition(db, run, "queued", p.subject)
        audit(
            db,
            p.subject,
            "run.catalog_authorized",
            run.id,
            catalog_approved_by=review.approved_by,
            source_revision=test.revision,
            content_sha256=test.content_hash,
            operation=requested_action,
        )
    else:
        transition(db, run, "pending_approval", p.subject)
    return run
