"""Actor-serialized bulk submission, durable controls and just-in-time dispatch checks."""

import time
from collections import Counter

from fastapi import HTTPException
from sqlalchemy import select

from ..auth.policy import authorize_execution, authorize_subject_execution
from ..errors import fail
from ..jobs.engine import TERMINAL, context_snapshot, eligibility, snapshot
from ..models import Actor, AtomicTest, Profile, Run, RunApproval, RunBatch
from ..schemas import RunRequest
from .common import audit, fingerprint, transition
from .runs import create_run

FAILURES = {"preparation_failed", "failed", "timed_out", "rejected", "inconclusive"}


def actor_for_write(db, actor_id):
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    return actor


def preview(db, settings, principal, actor, data):
    profile = db.get(Profile, str(data.execution_profile_id))
    items, bindings = [], []
    for guid in data.atomic_guids:
        test = db.get(AtomicTest, str(guid))
        item = {
            "guid": str(guid),
            "name": test.name if test else "Unknown definition",
            "technique": test.technique if test else "",
        }
        try:
            review = eligibility(db, test, actor, profile, settings)
            authorize_execution(settings, principal, actor, profile, test, review.risk_level, "execute")
            snap = snapshot(test, actor, profile, "execute", data.timeout_seconds, review)
            bindings.append({"snapshot": snap, "catalog_approved_by": review.approved_by})
            item.update(eligible=True, risk_level=review.risk_level, error="", message="")
        except HTTPException as error:
            detail = (
                error.detail
                if isinstance(error.detail, dict)
                else {"code": "invalid_state", "message": str(error.detail)}
            )
            item.update(
                eligible=False, risk_level="unavailable", error=detail["code"], message=detail["message"]
            )
            bindings.append({"guid": str(guid), "error": detail["code"]})
        items.append(item)
    return {
        "actor_id": actor.id,
        "hostname": actor.hostname,
        "execution_profile_id": str(data.execution_profile_id),
        "items": items,
        "selected_count": len(items),
        "eligible_count": sum(item["eligible"] for item in items),
        "preview_hash": fingerprint(
            {
                "actor_id": actor.id,
                "profile_id": str(data.execution_profile_id),
                "timeout": data.timeout_seconds,
                "items": bindings,
            }
        ),
    }


def submit(db, settings, principal, actor_id, data, key):
    if not key or len(key) > 128:
        fail("idempotency_required", "A 1–128 character Idempotency-Key is required", 422)
    request_hash = fingerprint({"actor_id": str(actor_id), **data.model_dump(mode="json")})
    existing = db.scalar(
        select(RunBatch).where(RunBatch.requested_by == principal.subject, RunBatch.idempotency_key == key)
    )
    if existing:
        if existing.request_hash != request_hash:
            fail("idempotency_conflict", "Key already used for a different batch")
        return existing
    actor = actor_for_write(db, actor_id)
    # Serialize retries after the actor lock, including concurrent PostgreSQL requests.
    existing = db.scalar(
        select(RunBatch).where(RunBatch.requested_by == principal.subject, RunBatch.idempotency_key == key)
    )
    if existing:
        if existing.request_hash != request_hash:
            fail("idempotency_conflict", "Key already used for a different batch")
        return existing
    selection = preview(db, settings, principal, actor, data)
    if selection["preview_hash"] != data.preview_hash:
        fail(
            "queue_preview_changed",
            "Selection or eligibility changed. Refresh the queue preview before submitting",
        )
    selected = [item for item in selection["items"] if item["eligible"]]
    if not selected:
        fail("queue_empty", "No approved compatible tests are eligible for this actor/profile")
    batch = RunBatch(
        actor_id=actor.id,
        profile_id=str(data.execution_profile_id),
        hostname=actor.hostname,
        name=data.name.strip() or "Selected catalog tests",
        reason=data.reason,
        requested_by=principal.subject,
        idempotency_key=key,
        request_hash=request_hash,
        approval_mode=settings.approval_mode,
        failure_policy=data.failure_policy,
        expires_at=time.time() + settings.queue_lifetime_seconds,
    )
    db.add(batch)
    db.flush()
    for index, item in enumerate(selected):
        create_run(
            db,
            settings,
            principal,
            RunRequest(
                atomic_guid=item["guid"],
                actor_id=actor.id,
                execution_profile_id=data.execution_profile_id,
                reason=data.reason,
                timeout_seconds=data.timeout_seconds,
            ),
            f"batch:{batch.id}:{index}",
            batch_id=batch.id,
        )
    audit(
        db,
        principal.subject,
        "queue.submitted",
        batch.id,
        actor_id=actor.id,
        count=len(selected),
        excluded=selection["selected_count"] - len(selected),
        failure_policy=batch.failure_policy,
    )
    return batch


def items(db, batch):
    return db.scalars(
        select(Run).where(Run.batch_id == batch.id).order_by(Run.queue_position, Run.created_at, Run.id)
    ).all()


def view(db, batch):
    runs = items(db, batch)
    counts = dict(Counter(run.status for run in runs))
    active = any(run.status in {"claimed", "running"} for run in runs)
    waiting = [run for run in runs if run.status not in TERMINAL]
    if active:
        status = "pausing" if batch.paused else "cancelling" if batch.cancelled else "running"
    elif batch.cancelled:
        status = "expired" if batch.pause_reason == "queue_expired" else "cancelled"
    elif not waiting:
        status = "completed_with_errors" if any(run.status in FAILURES for run in runs) else "completed"
    elif batch.expires_at <= time.time():
        status = "expired"
    elif batch.paused:
        status = "paused"
    else:
        status = (
            "awaiting_approval"
            if waiting[0].status == "pending_approval"
            else "preparing"
            if waiting[0].status == "preparing"
            else "queued"
        )
    return {
        "id": batch.id,
        "actor_id": batch.actor_id,
        "hostname": batch.hostname,
        "execution_profile_id": batch.profile_id,
        "name": batch.name,
        "reason": batch.reason,
        "requested_by": batch.requested_by,
        "approval_mode": batch.approval_mode,
        "failure_policy": batch.failure_policy,
        "paused": batch.paused,
        "pause_reason": batch.pause_reason,
        "cancelled": batch.cancelled,
        "status": status,
        "created_at": batch.created_at,
        "expires_at": batch.expires_at,
        "total": len(runs),
        "finished": len(runs) - len(waiting),
        "counts": counts,
        "items": [
            {
                "run_id": run.id,
                "guid": run.guid,
                "name": run.snapshot["test_name"],
                "technique": run.snapshot["technique"],
                "preparation_error": run.preparation_error,
                "status": run.status,
                "queue_position": run.queue_position,
                "risk_level": run.snapshot["risk_level"],
            }
            for run in runs
        ],
    }


def pause(db, batch, reason, run_id=None, identity="system:queue"):
    if batch.paused and batch.pause_reason == reason and batch.pause_run_id == run_id:
        return
    batch.paused, batch.pause_reason, batch.pause_run_id = True, reason, run_id
    audit(db, identity, "queue.paused", batch.id, reason=reason, run_id=run_id)


def cancel(db, batch, identity, reason="cancelled"):
    if batch.cancelled:
        return
    batch.cancelled, batch.paused, batch.pause_reason = True, False, reason
    for run in items(db, batch):
        if run.status in {"pending_approval", "queued", "preparing"}:
            run.cancel_requested = True
            transition(db, run, "cancelled", identity)
    audit(db, identity, "queue.cancelled", batch.id, reason=reason)


def control(db, settings, principal, batch, action):
    actor_for_write(db, batch.actor_id)
    db.refresh(batch)
    if all(run.status in TERMINAL for run in items(db, batch)):
        if action == "cancel":
            return
        fail("queue_terminal", "This batch has no remaining work")
    if action == "cancel":
        cancel(db, batch, principal.subject)
        return
    if batch.cancelled or batch.expires_at <= time.time():
        fail("queue_terminal", "This batch is cancelled or expired")
    if action == "pause":
        pause(db, batch, "manual", identity=principal.subject)
        return
    if batch.approval_mode != settings.approval_mode:
        fail("queue_mode_changed", "Cancel and resubmit this batch under the current approval mode")
    if db.scalar(
        select(Run.id)
        .where(Run.actor_id == batch.actor_id, Run.status == "inconclusive", Run.reconciled.is_(False))
        .limit(1)
    ):
        fail(
            "queue_reconciliation_required",
            "Reconcile the actor's uncertain execution outcome before resuming",
        )
    blocked = db.get(Run, batch.pause_run_id) if batch.pause_run_id else None
    if batch.pause_reason == "approval_expired" and blocked and blocked.status == "pending_approval":
        fail("queue_approval_required", "Renew the expired human approval before resuming")
    batch.acknowledged_position = max(
        (run.queue_position for run in items(db, batch) if run.status in TERMINAL), default=0
    )
    batch.paused, batch.pause_reason, batch.pause_run_id = False, "", None
    audit(db, principal.subject, "queue.resumed", batch.id)


def prepare_dispatch(db, run, actor, settings):
    """Return ready/wait/skip. A wait holds later actor work in FIFO order."""
    if not run.batch_id:
        return "ready"
    batch = db.get(RunBatch, run.batch_id)
    if not batch:
        fail("queue_missing", "Execution batch is missing")
    if batch.cancelled:
        transition(db, run, "cancelled", "system:queue")
        return "skip"
    if batch.expires_at <= time.time():
        cancel(db, batch, "system:queue", "queue_expired")
        return "skip"
    if batch.approval_mode != settings.approval_mode:
        pause(db, batch, "approval_mode_changed", run.id)
        return "wait"
    if batch.paused or run.status == "pending_approval":
        return "wait"
    try:
        test, profile = db.get(AtomicTest, run.guid), db.get(Profile, run.profile_id)
        review = eligibility(db, test, actor, profile, settings)
        authorize_subject_execution(
            settings, batch.requested_by, actor, profile, test, review.risk_level, "execute"
        )
        current = context_snapshot(run, test, actor, profile, review)
        if fingerprint(current) != run.snapshot_hash or fingerprint(run.snapshot) != run.snapshot_hash:
            fail("queue_definition_changed", "The queued definition or execution identity changed")
    except HTTPException as error:
        code = error.detail["code"] if isinstance(error.detail, dict) else "invalid_state"
        if code == "catalog_update_pending":
            return "wait"
        transition(db, run, "rejected", "system:queue:" + code)
        pause(db, batch, code, run.id)
        return "wait"
    approval = db.get(RunApproval, run.id)
    if (
        not approval
        or approval.decision != "approved"
        or approval.snapshot_hash != run.snapshot_hash
        or approval.authorization_source != batch.approval_mode
    ):
        transition(db, run, "rejected", "system:queue:invalid-approval")
        pause(db, batch, "approval_invalid", run.id)
        return "wait"
    if approval.expires_at <= time.time():
        if batch.approval_mode == "catalog":
            # Standing catalog authorization is rechecked above. This never renews human approvals.
            approval.expires_at, approval.approved_by = (
                time.time() + settings.approval_seconds,
                review.approved_by,
            )
            audit(
                db,
                "system:queue",
                "queue.catalog_dispatch_authorized",
                batch.id,
                run_id=run.id,
                catalog_approved_by=review.approved_by,
            )
        else:
            approval.decision = "expired"
            transition(db, run, "pending_approval", "system:queue:approval-expired")
            pause(db, batch, "approval_expired", run.id)
            return "wait"
    return "ready"
