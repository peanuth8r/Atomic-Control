import re
import secrets
import time
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..auth import Principal, agent, human, viewer
from ..auth.policy import authorize_execution
from ..catalog.parser import approved, execution_platforms, valid_review
from ..catalog.validation import pinned
from ..db import session
from ..errors import fail
from ..jobs.engine import TERMINAL, claim, eligibility, online, proof, reap, result
from ..models import (
    Actor,
    AtomicTest,
    Attempt,
    Audit,
    Cleanup,
    Credential,
    Enrollment,
    Event,
    ExecutionBinding,
    Lease,
    Log,
    Profile,
    Run,
    RunApproval,
    RunBatch,
    TestApproval,
)
from ..schemas import (
    ActorDeletionResponse,
    ActorResponse,
    EnrollmentRequest,
    EnrollmentTokenRequest,
    Heartbeat,
    LeaseProof,
    Paged,
    ProfileRequest,
    ProfileResponse,
    Reason,
    Reconciliation,
    Result,
    RetireActorRequest,
    RunRequest,
    RunResponse,
    TestResponse,
    TestReview,
)
from ..services import catalog_deployments, file_plans, profile_sync, test_artifacts
from ..services.actor_lifecycle import deletion_receipt, retire
from ..services.actor_status import require_current_actor
from ..services.agent_settings import enrollment_seconds
from ..services.common import audit, digest, fingerprint, transition
from ..services.runs import create_run

router = APIRouter(prefix="/api/v1")


def need(db, model, key):
    item = db.get(model, str(key))
    if not item:
        fail("not_found", "Resource does not exist", 404)
    return item


def page(items, limit, offset):
    return {"items": items[offset : offset + limit], "total": len(items), "limit": limit, "offset": offset}


def test_view(db, item, review=None, resolved=False):
    review = valid_review(item, review) if resolved else approved(db, item)
    return {
        "artifact": artifact.descriptor if (artifact := test_artifacts.artifact_for(db, item)) else None,
        "file_plan": file_plans.plan_view(plan)
        if (plan := file_plans.valid_plan(db, item, review))
        else None,
        "artifact_approved": bool(
            plan or (review and artifact and review.artifact == artifact.descriptor and not artifact.revoked)
        ),
        "guid": item.guid,
        "name": item.name,
        "technique": item.technique,
        "revision": item.revision,
        "content_sha256": item.content_hash,
        "definition": item.definition,
        "approved": bool(review),
        "risk_level": review.risk_level if review else "unreviewed",
        "allowed_profiles": review.allowed_profiles if review else [],
        "simulated": item.simulated,
        "catalog_source": item.catalog_source,
        "source_path": item.source_path,
        "active": item.active,
        "execution_ready": item.active and not item.simulated and pinned(item.revision),
    }


def profile_view(profile):
    return {
        k: getattr(profile, k)
        for k in [
            "id",
            "actor_id",
            "profile_key",
            "display_name",
            "account",
            "expected_sid",
            "privilege",
            "logon_type",
            "enabled",
            "healthy",
        ]
    }


def actor_view(db, actor, settings):
    lease = db.get(Lease, actor.id)
    return {
        "workspace_status": "orphaned"
        if actor.workspace_residue
        else attempt.workspace_status
        if lease and (attempt := db.get(Attempt, lease.attempt_id))
        else "not_required",
        "delivery_mode": actor.delivery_mode,
        "artifact_protocol": actor.artifact_protocol,
        "profile_sync": profile_sync.view(db, actor),
        "catalog": catalog_deployments.view(db, actor),
        "retired_at": actor.retired_at,
        "retired_by": actor.retired_by,
        "retirement_reason": actor.retirement_reason,
        "id": actor.id,
        "hostname": actor.hostname,
        "registration_state": actor.registration_state,
        "os": actor.os,
        "os_version": actor.os_version,
        "agent_version": actor.agent_version,
        "revision": actor.revision,
        "enabled": actor.enabled,
        "online": online(actor, settings),
        "last_heartbeat": actor.last_heartbeat,
        "health": actor.health,
        "active_job": lease.run_id if lease else None,
        "simulated": actor.simulated,
        "profiles": [
            profile_view(p) for p in db.scalars(select(Profile).where(Profile.actor_id == actor.id)).all()
        ],
    }


def run_view(db, run):
    approval = db.get(RunApproval, run.id)
    cleanups = db.scalars(select(Cleanup).where(Cleanup.parent_id == run.id)).all()
    cleanup_status = cleanups[-1].status if cleanups else "not_requested"
    if not run.snapshot["definition"].get("executor", {}).get("cleanup_command"):
        cleanup_status = "not_supported"
    binding = db.get(ExecutionBinding, run.id)
    return {
        "preparation": file_plans.preparation_view(db, run),
        "execution_artifact": binding.snapshot.get("artifact") if binding else run.snapshot.get("artifact"),
        "workspace_status": attempt.workspace_status
        if (attempt := db.scalar(select(Attempt).where(Attempt.run_id == run.id)))
        else "not_required",
        "run_id": run.id,
        "batch_id": run.batch_id,
        "queue_position": run.queue_position,
        "status": run.status,
        "actor_id": run.actor_id,
        "execution_profile_id": run.profile_id,
        "approval_required": run.status == "pending_approval",
        "snapshot": run.snapshot,
        "result": run.result,
        "created_at": run.created_at,
        "updated_at": run.updated_at,
        "requested_by": run.requested_by,
        "reason": run.reason,
        "action": run.action,
        "parent_id": run.parent_id,
        "cancel_requested": run.cancel_requested,
        "cleanup_status": cleanup_status,
        "approved_by": approval.approved_by if approval else None,
        "authorization_source": approval.authorization_source if approval else None,
        "events": [
            {"status": e.status, "identity": e.identity, "timestamp": e.timestamp}
            for e in db.scalars(select(Event).where(Event.run_id == run.id).order_by(Event.timestamp)).all()
        ],
    }


@router.get("/me")
def me(request: Request, p: Principal = Depends(viewer)):
    expires = getattr(request.state, "browser_session_expires_at", None)
    return {
        "session_expires_at": expires,
        "session_expires_in": max(0, expires - time.time()) if expires else None,
        "subject": p.subject,
        "username": p.username or None,
        "roles": sorted(p.roles),
        "mode": request.app.state.settings.mode,
        "dev_auth": request.app.state.settings.dev_auth,
        "approval_mode": request.app.state.settings.approval_mode,
    }


@router.get("/tests", response_model=Paged[TestResponse])
def tests(
    q: str = "",
    approved_only: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(session),
    p: Principal = Depends(viewer),
):
    query = select(AtomicTest).where(AtomicTest.active.is_(True), AtomicTest.simulated.is_(False))
    if q:
        query = query.where(
            or_(
                AtomicTest.name.icontains(q, autoescape=True),
                AtomicTest.technique.icontains(q, autoescape=True),
            )
        )
    if approved_only:
        query = query.join(TestApproval, TestApproval.guid == AtomicTest.guid).where(
            TestApproval.approved.is_(True),
            TestApproval.content_hash == AtomicTest.content_hash,
            TestApproval.revision == AtomicTest.revision,
        )
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    items = db.scalars(
        query.order_by(AtomicTest.technique, AtomicTest.name, AtomicTest.guid).offset(offset).limit(limit)
    ).all()
    reviews = {
        r.guid: r
        for r in db.scalars(select(TestApproval).where(TestApproval.guid.in_([t.guid for t in items]))).all()
    }
    return {
        "items": [test_view(db, t, reviews.get(t.guid), resolved=True) for t in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/tests/{guid}", response_model=TestResponse)
def test_detail(guid: UUID, db: Session = Depends(session), p: Principal = Depends(viewer)):
    return test_view(db, need(db, AtomicTest, guid))


@router.get("/techniques")
def techniques(db: Session = Depends(session), p: Principal = Depends(viewer)):
    return sorted(
        {
            t.technique
            for t in db.scalars(
                select(AtomicTest).where(AtomicTest.active.is_(True), AtomicTest.simulated.is_(False))
            ).all()
        }
    )


@router.post("/tests/{guid}/review")
def review_test(
    guid: UUID,
    data: TestReview,
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    p.require("administrator")
    test = need(db, AtomicTest, guid)
    if not test.active:
        fail("test_removed", "Removed catalog definitions cannot be approved")
    if test.simulated or not pinned(test.revision):
        fail(
            "catalog_not_pinned",
            "Re-upload with the exact source Git commit before approval",
        )
    platforms = execution_platforms(test.definition)
    if not platforms:
        fail("executor_unapproved", "Supported tests use Windows PowerShell/Command Prompt or Linux bash/sh")
    if (
        test.definition.get("executor", {}).get("elevation_required", False)
        and "standard-user" in data.allowed_profiles
    ):
        fail("incompatible_profile", "Elevated tests cannot be approved for Standard User")
    if data.content_sha256 != test.content_hash or data.source_revision != test.revision:
        fail("catalog_mismatch", "Review must match current hash and revision")
    artifact = test_artifacts.artifact_for(db, test) if data.artifact_digest else None
    if data.artifact_digest and (not artifact or artifact.digest != data.artifact_digest):
        fail("artifact_mismatch", "Prepare and review the current packaged files before approval")
    plan = (
        None
        if data.artifact_digest
        else file_plans.resolve_approval(db, test, data, request.app.state.settings, p.subject)
    )
    if plan:
        compatible = test_artifacts.artifact_for(db, test)
        if compatible and compatible.descriptor["manifest"] == plan.manifest:
            artifact = compatible
        from ..models import ArtifactBuild

        failed_build = db.get(ArtifactBuild, plan.hash)
        if failed_build and failed_build.status == "failed":
            (
                failed_build.status,
                failed_build.owner,
                failed_build.attempts,
                failed_build.retry_at,
                failed_build.deadline,
                failed_build.error,
                failed_build.error_code,
            ) = "pending", "", 0, 0, 0, "", ""
        plan.approval = {
            "allowed_profiles": data.allowed_profiles,
            "allowed_platforms": platforms,
            "risk_level": data.risk_level,
            "approved_by": p.subject,
            "approved": True,
        }
        plan.revoked = False
    if artifact:
        artifact.revoked = False
        artifact.approval = {
            "allowed_profiles": data.allowed_profiles,
            "allowed_platforms": platforms,
            "risk_level": data.risk_level,
            "approved_by": p.subject,
            "approved": True,
        }
    db.merge(
        TestApproval(
            plan_hash=plan.hash if plan else "",
            artifact=artifact.descriptor if artifact else None,
            guid=test.guid,
            content_hash=test.content_hash,
            revision=test.revision,
            allowed_profiles=data.allowed_profiles,
            allowed_platforms=platforms,
            risk_level=data.risk_level,
            approved_by=p.subject,
            approved=True,
        )
    )
    audit(
        db,
        p.subject,
        "catalog.review",
        test.guid,
        content_sha256=test.content_hash,
        source_revision=test.revision,
        plan_hash=plan.hash if plan else "",
        risk_level=data.risk_level,
        allowed_profiles=data.allowed_profiles,
    )
    return {"approved": True}


@router.post("/tests/{guid}/revoke")
def revoke_test(guid: UUID, data: Reason, db: Session = Depends(session), p: Principal = Depends(human)):
    p.require("administrator")
    review = need(db, TestApproval, guid)
    review.approved = False
    test_artifacts.revoke_artifacts(db, str(guid))
    file_plans.revoke_plans(db, str(guid))
    audit(db, p.subject, "catalog.revoke", str(guid), reason=data.reason)
    return {"approved": False}


@router.get("/actors", response_model=Paged[ActorResponse])
def actors(
    request: Request,
    include_retired: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(session),
    p: Principal = Depends(viewer),
):
    query = select(Actor).where(Actor.simulated.is_(False))
    if not include_retired:
        query = query.where(Actor.registration_state != "retired")
    return page(
        [actor_view(db, a, request.app.state.settings) for a in db.scalars(query).all()],
        limit,
        offset,
    )


@router.get("/actors/{actor_id}", response_model=ActorResponse)
def actor_detail(
    actor_id: UUID, request: Request, db: Session = Depends(session), p: Principal = Depends(viewer)
):
    return actor_view(db, need(db, Actor, actor_id), request.app.state.settings)


@router.get("/actors/{actor_id}/profiles", response_model=list[ProfileResponse])
def profiles(actor_id: UUID, db: Session = Depends(session), p: Principal = Depends(viewer)):
    need(db, Actor, actor_id)
    return [
        profile_view(x) for x in db.scalars(select(Profile).where(Profile.actor_id == str(actor_id))).all()
    ]


@router.post("/actors/{actor_id}/profiles")
def provision_profile(
    actor_id: UUID, data: ProfileRequest, db: Session = Depends(session), p: Principal = Depends(human)
):
    p.require("administrator")
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    require_current_actor(actor)
    if actor.os == "linux":
        if not re.fullmatch(r"uid:(?:0|[1-9]\d{0,9})", data.expected_sid) or not re.fullmatch(
            r"[a-z_][a-z0-9_-]{0,31}", data.account
        ):
            fail("invalid_profile", "Linux profiles require a local account name and uid:<numeric UID>", 422)
        if (data.expected_sid == "uid:0") != (data.privilege == "elevated"):
            fail("invalid_profile", "Only UID 0 may be an elevated Linux profile", 422)
    elif not data.expected_sid.startswith("S-1-5-"):
        fail("invalid_profile", "Windows profiles require a Windows SID", 422)
    if (data.profile_key == "local-admin") != (data.privilege == "elevated"):
        fail("invalid_profile", "Profile name and privilege disagree", 422)
    if db.scalar(
        select(Profile).where(Profile.actor_id == str(actor_id), Profile.profile_key == data.profile_key)
    ):
        fail(
            "immutable_profile",
            "Existing profiles cannot be overwritten; disable and provision a new identity",
        )
    profile = Profile(
        actor_id=str(actor_id),
        **data.model_dump(),
        healthy=False,
        logon_type="systemd" if actor.os == "linux" else "batch",
    )
    db.add(profile)
    db.flush()
    audit(db, p.subject, "profile.provision", profile.id)
    profile_sync.reconcile(db, actor)
    return profile_view(profile)


@router.post("/actors/{actor_id}/enable")
@router.post("/actors/{actor_id}/disable")
def toggle_actor(
    actor_id: UUID, request: Request, db: Session = Depends(session), p: Principal = Depends(human)
):
    p.require("administrator")
    action = request.url.path.rsplit("/", 1)[-1]
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    require_current_actor(actor)
    actor.enabled = action == "enable"
    if not actor.enabled:
        for run in db.scalars(
            select(Run).where(Run.actor_id == actor.id, Run.status.in_(["claimed", "running"]))
        ):
            run.cancel_requested = True
    audit(db, p.subject, "actor." + action, actor.id)
    return {"enabled": actor.enabled}


@router.post("/actors/{actor_id}/retire", response_model=ActorDeletionResponse)
def retire_actor(
    actor_id: UUID,
    data: RetireActorRequest,
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    p.require("administrator")
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        receipt = deletion_receipt(db, actor_id)
        if receipt is None:
            fail("not_found", "Actor does not exist", 404)
        hostname = receipt["hostname"]
    else:
        hostname = actor.hostname
    if data.hostname != hostname:
        fail("hostname_confirmation_mismatch", "Type the actor's exact hostname to confirm deletion", 422)
    return retire(db, actor, p.subject, data.reason or "") if actor else receipt


@router.post("/runs", response_model=RunResponse, status_code=201)
def request_run(
    data: RunRequest,
    request: Request,
    idempotency_key: str = Header(),
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    return run_view(db, create_run(db, request.app.state.settings, p, data, idempotency_key))


@router.get("/runs", response_model=Paged[RunResponse])
def runs(
    status: str = "",
    batch_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(session),
    p: Principal = Depends(viewer),
):
    reap(db)
    query = select(Run).order_by(Run.created_at.desc())
    if status:
        query = query.where(Run.status == status)
    if batch_id:
        query = query.where(Run.batch_id == str(batch_id))
    return page([run_view(db, r) for r in db.scalars(query).all()], limit, offset)


@router.get("/runs/{run_id}", response_model=RunResponse)
def run_detail(run_id: UUID, db: Session = Depends(session), p: Principal = Depends(viewer)):
    reap(db)
    return run_view(db, need(db, Run, run_id))


@router.get("/runs/{run_id}/logs")
def logs(run_id: UUID, db: Session = Depends(session), p: Principal = Depends(viewer)):
    need(db, Run, run_id)
    log = db.get(Log, str(run_id))
    return {"content": log.content if log else "", "truncated": log.truncated if log else False}


@router.post("/runs/{run_id}/cancel")
def cancel(run_id: UUID, data: Reason, db: Session = Depends(session), p: Principal = Depends(human)):
    p.require("operator")
    run = need(db, Run, run_id)
    if run.status in TERMINAL:
        fail("invalid_state", "Run already terminal")
    run.cancel_requested = True
    if run.status in {"pending_approval", "queued", "preparing"}:
        transition(db, run, "cancelled", p.subject)
    audit(db, p.subject, "run.cancel-requested", run.id, reason=data.reason)
    return run_view(db, run)


@router.post("/runs/{run_id}/cleanup", response_model=RunResponse, status_code=201)
def cleanup(
    run_id: UUID,
    data: Reason,
    request: Request,
    idempotency_key: str = Header(),
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    parent = need(db, Run, run_id)
    if parent.action != "execute" or parent.status not in TERMINAL - {"rejected", "preparation_failed"}:
        fail("invalid_state", "Cleanup requires a terminal execution")
    if not parent.snapshot["definition"].get("executor", {}).get("cleanup_command"):
        fail("cleanup_not_supported", "No reviewed cleanup command")
    request_data = RunRequest(
        atomic_guid=parent.guid,
        actor_id=parent.actor_id,
        execution_profile_id=parent.profile_id,
        reason=data.reason,
        timeout_seconds=parent.snapshot["timeout_seconds"],
    )
    # Cleanup must use the same reviewed definition and identity as the execution.
    test = need(db, AtomicTest, parent.guid)
    if not file_plans.on_demand(parent) and (
        test.content_hash != parent.snapshot["content_sha256"]
        or test.revision != parent.snapshot["source_revision"]
    ):
        fail("catalog_mismatch", "Original catalog must be restored and reviewed before cleanup")
    return run_view(
        db, create_run(db, request.app.state.settings, p, request_data, idempotency_key, "cleanup", parent.id)
    )


@router.post("/runs/{run_id}/retry-preparation", response_model=RunResponse, status_code=201)
def retry_preparation(
    run_id: UUID,
    data: Reason,
    request: Request,
    idempotency_key: str = Header(),
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    original = need(db, Run, run_id)
    if original.status != "preparation_failed" or db.scalar(
        select(Attempt.id).where(Attempt.run_id == original.id)
    ):
        fail("retry_not_allowed", "Only packaging failures before an actor attempt can be retried")
    if original.preparation_code == "artifact_integrity_failed":
        fail("review_required", "Review the test after an integrity failure")
    p.require("operator")
    actor = db.get(Actor, original.actor_id, with_for_update=True)
    if actor is None:
        fail("not_found", "Original actor no longer exists", 404)
    existing = db.scalar(
        select(Run).where(Run.requested_by == p.subject, Run.idempotency_key == idempotency_key)
    )
    value = RunRequest(
        atomic_guid=original.guid,
        actor_id=original.actor_id,
        execution_profile_id=original.profile_id,
        reason=data.reason,
        timeout_seconds=original.snapshot["timeout_seconds"],
        action="check" if original.action == "check" else "execute",
    )
    retry = create_run(
        db, request.app.state.settings, p, value, idempotency_key, original.action, original.parent_id
    )
    if retry.snapshot_hash != original.snapshot_hash:
        fail(
            "approval_invalidated", "Content or execution identity changed; submit a new request after review"
        )
    if existing is None:
        from ..models import ArtifactBuild

        build = db.get(ArtifactBuild, original.snapshot["file_plan"]["hash"], with_for_update=True)
        if build and build.status == "failed":
            (
                build.status,
                build.owner,
                build.attempts,
                build.retry_at,
                build.deadline,
                build.error,
                build.error_code,
            ) = "pending", "", 0, 0, 0, "", ""
        audit(db, p.subject, "preparation.retry-requested", retry.id, previous_run_id=original.id)
    return run_view(db, retry)


@router.get("/approvals")
def approvals(db: Session = Depends(session), p: Principal = Depends(viewer)):
    return {
        "items": [
            run_view(db, r)
            for r in db.scalars(
                select(Run).where(Run.status == "pending_approval").order_by(Run.created_at)
            ).all()
        ]
    }


@router.post("/runs/{run_id}/approve", response_model=RunResponse)
def approve(
    run_id: UUID,
    data: Reason,
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    p.require("approver")
    run = need(db, Run, run_id)
    actor = db.get(Actor, run.actor_id, with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    db.refresh(run)
    if run.snapshot["privilege"] == "elevated":
        p.require("privileged_approver")
        if run.requested_by == p.subject:
            fail("self_approval", "Requester cannot approve their own privileged execution", 403)
    if run.status != "pending_approval":
        fail("invalid_state", "Only pending requests can be approved")
    if run.batch_id:
        batch = need(db, RunBatch, run.batch_id)
        if batch.cancelled or batch.expires_at <= time.time():
            fail("queue_terminal", "This batch is cancelled or expired")
        if batch.approval_mode != request.app.state.settings.approval_mode:
            fail("queue_mode_changed", "Cancel and resubmit under the current approval mode")
    settings = request.app.state.settings
    profile, test = (
        need(db, Profile, run.profile_id),
        need(db, AtomicTest, run.guid),
    )
    from ..jobs.engine import context_snapshot, run_context

    test, stored_review = run_context(db, run)
    review = eligibility(db, test, actor, profile, settings, stored_review)
    authorize_execution(settings, p, actor, profile, test, review.risk_level, "approve")
    if fingerprint(context_snapshot(run, test, actor, profile, review)) != run.snapshot_hash:
        fail("approval_invalidated", "Execution context changed; submit a new request")
    db.merge(
        RunApproval(
            run_id=run.id,
            approved_by=p.subject,
            snapshot_hash=run.snapshot_hash,
            expires_at=time.time() + settings.approval_seconds,
            decision="approved",
        )
    )
    transition(db, run, "queued", p.subject)
    audit(db, p.subject, "run.approve", run.id, reason=data.reason)
    return run_view(db, run)


@router.post("/runs/{run_id}/reject")
def reject(run_id: UUID, data: Reason, db: Session = Depends(session), p: Principal = Depends(human)):
    p.require("approver")
    run = need(db, Run, run_id)
    if run.status != "pending_approval":
        fail("invalid_state", "Only pending requests can be rejected")
    db.merge(
        RunApproval(
            run_id=run.id,
            approved_by=p.subject,
            snapshot_hash=run.snapshot_hash,
            expires_at=time.time(),
            decision="rejected",
        )
    )
    transition(db, run, "rejected", p.subject)
    audit(db, p.subject, "run.reject", run.id, reason=data.reason)
    return run_view(db, run)


@router.post("/runs/{run_id}/reconcile")
def reconcile(
    run_id: UUID, data: Reconciliation, db: Session = Depends(session), p: Principal = Depends(human)
):
    p.require("administrator")
    run = need(db, Run, run_id)
    attempt = db.scalar(select(Attempt).where(Attempt.run_id == run.id))
    removal_hold = bool(
        file_plans.on_demand(run) and attempt and attempt.result_hash and attempt.workspace_status != "purged"
    )
    if run.status != "inconclusive" and not removal_hold:
        fail(
            "invalid_state",
            "Only uncertain executions or downloaded-file removal holds require reconciliation",
        )
    lease = db.get(Lease, run.actor_id)
    if file_plans.on_demand(run):
        attempt = db.scalar(select(Attempt).where(Attempt.run_id == run.id))
        if attempt and attempt.workspace_status != "purged":
            if not data.workspace_removed:
                fail(
                    "workspace_not_removed",
                    "Confirm host process termination and file removal before reconciliation",
                )
            attempt.workspace_status = "purged"
            audit(db, p.subject, "artifact.workspace-admin-confirmed", run.id, reason=data.reason)
    if lease and lease.run_id == run.id:
        db.delete(lease)
    run.reconciled = True
    audit(db, p.subject, "run.reconcile", run.id, reason=data.reason)
    return {"reconciled": True, "status": run.status}


@router.get("/audit")
def audit_list(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(session),
    p: Principal = Depends(viewer),
):
    items = db.scalars(select(Audit).order_by(Audit.timestamp.desc())).all()
    return page(
        [
            {
                "id": a.id,
                "identity": a.identity,
                "action": a.action,
                "resource": a.resource,
                "timestamp": a.timestamp,
                "details": a.details,
            }
            for a in items
        ],
        limit,
        offset,
    )


@router.post("/enrollment-tokens")
def enrollment_token(
    data: EnrollmentTokenRequest, db: Session = Depends(session), p: Principal = Depends(human)
):
    p.require("administrator")
    existing = db.scalar(
        select(Actor).where(func.lower(Actor.hostname) == data.hostname.lower()).with_for_update()
    )
    if existing:
        require_current_actor(existing)
    token = secrets.token_urlsafe(48)
    seconds = enrollment_seconds(db)
    db.add(
        Enrollment(digest=digest(token), os=data.os, hostname=data.hostname, expires_at=time.time() + seconds)
    )
    audit(db, p.subject, "agent.enrollment-issued", data.hostname)
    return {"token": token, "expires_in": seconds}


@router.post("/agents/enroll")
def enroll(data: EnrollmentRequest, request: Request, db: Session = Depends(session)):
    settings = request.app.state.settings
    token = db.scalar(select(Enrollment).where(Enrollment.digest == digest(data.token)))
    if not token:
        fail("invalid_enrollment", "Invalid, expired, or consumed enrollment token", 401)
    # Lock actor before token, matching retirement and package generation.
    actor = (
        db.get(Actor, token.actor_id, with_for_update=True)
        if token.actor_id
        else db.scalar(
            select(Actor).where(func.lower(Actor.hostname) == data.hostname.lower()).with_for_update()
        )
    )
    token = db.scalar(
        select(Enrollment)
        .where(Enrollment.id == token.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if (
        not token
        or token.used
        or token.expires_at <= time.time()
        or token.hostname != data.hostname
        or token.os != data.os
    ):
        fail("invalid_enrollment", "Invalid, expired, or consumed enrollment token", 401)
    if token.actor_id:
        if (
            not actor
            or actor.id != token.actor_id
            or actor.hostname != data.hostname
            or actor.simulated
            or actor.os != data.os
        ):
            fail("invalid_enrollment", "Enrollment does not match a real actor", 401)
        require_current_actor(actor)
        if actor.registration_state == "enrolled":
            if (
                actor.enabled
                or db.get(Lease, actor.id) is not None
                or catalog_deployments.applying(db, actor)
            ):
                fail(
                    "reenrollment_blocked",
                    "Disable the actor and reconcile active work before replacing credentials",
                )
            for previous in db.scalars(select(Credential).where(Credential.actor_id == actor.id)):
                previous.revoked = True
        for profile in db.scalars(select(Profile).where(Profile.actor_id == actor.id)):
            profile.healthy = False
        actor.agent_version, actor.os_version = data.agent_version, data.os_version
        actor.registration_state, actor.last_heartbeat, actor.health = "enrolled", 0, "unknown"
    else:
        if actor:
            require_current_actor(actor)
            fail("actor_exists", "Hostname already enrolled")
        actor = Actor(
            hostname=data.hostname,
            os=data.os,
            os_version=data.os_version,
            agent_version=data.agent_version,
            simulated=False,
        )
        db.add(actor)
        db.flush()
    token.used = True
    credential = secrets.token_urlsafe(48)
    expires = time.time() + settings.credential_seconds
    db.add(Credential(actor_id=actor.id, digest=digest(credential), expires_at=expires))
    audit(db, "agent:" + actor.id, "agent.enrolled", actor.id)
    return {"actor_id": actor.id, "credential": credential, "expires_at": expires}


@router.post("/agents/credentials/rotate")
def rotate(request: Request, actor: Actor = Depends(agent), db: Session = Depends(session)):
    token = secrets.token_urlsafe(48)
    # Brief overlap allows crash recovery if the response is lost.
    for credential in db.scalars(
        select(Credential).where(Credential.actor_id == actor.id, Credential.revoked.is_(False))
    ):
        credential.expires_at = min(credential.expires_at, time.time() + 120)
    expires = time.time() + request.app.state.settings.credential_seconds
    db.add(Credential(actor_id=actor.id, digest=digest(token), expires_at=expires))
    audit(db, "agent:" + actor.id, "credential.rotated", actor.id)
    return {"credential": token, "expires_at": expires}


@router.post("/agents/heartbeat")
def heartbeat(data: Heartbeat, actor: Actor = Depends(agent), db: Session = Depends(session)):
    if actor.hostname != data.hostname or actor.os != data.os:
        fail("identity_mismatch", "Hostname does not match enrolled actor", 403)
    if data.profile_sync_protocol == 1 and not data.profile_config_hash:
        fail("invalid_profile_hash", "Managed profiles require the applied configuration hash", 422)
    if data.delivery_mode == "on_demand" and data.artifact_protocol != 1:
        fail("artifact_protocol_required", "On-demand delivery requires artifact protocol 1", 422)
    if actor.delivery_mode != data.delivery_mode and (
        db.get(Lease, actor.id) is not None or catalog_deployments.applying(db, actor)
    ):
        fail("actor_busy", "Finish current work before changing delivery mode")
    if actor.delivery_mode != data.delivery_mode:
        for pending_run in db.scalars(
            select(Run).where(
                Run.actor_id == actor.id, Run.status.in_(["queued", "pending_approval", "preparing"])
            )
        ):
            if file_plans.on_demand(pending_run) != (data.delivery_mode == "on_demand"):
                transition(db, pending_run, "rejected", "system:delivery-mode-changed")
        old_catalog = catalog_deployments.latest(db, actor)
        if data.delivery_mode == "on_demand" and old_catalog and old_catalog.status in {"pending", "failed"}:
            old_catalog.status = "superseded"
        audit(
            db, "agent:" + actor.id, "actor.delivery-mode-changed", actor.id, delivery_mode=data.delivery_mode
        )
    actor.delivery_mode, actor.artifact_protocol = data.delivery_mode, data.artifact_protocol
    actor.workspace_residue = data.workspace_residue
    actor.last_heartbeat, actor.health = time.time(), data.health
    actor.os_version, actor.agent_version = data.os_version, data.agent_version
    actor.catalog_sync_protocol = data.catalog_sync_protocol if actor.os == "linux" else 0
    actor.catalog_health = data.catalog_health
    catalog = catalog_deployments.latest(db, actor)
    if actor.delivery_mode == "on_demand":
        actor.revision, actor.catalog_health = "", "ready"
    elif actor.catalog_sync_protocol == 1 or catalog:
        verified = bool(
            catalog
            and catalog.status == "applied"
            and data.catalog_health == "ready"
            and data.revision == catalog.revision
            and data.catalog_config_hash == catalog.payload_hash
        )
        actor.revision = data.revision if verified else ""
        if data.catalog_health == "ready" and not verified:
            actor.catalog_health = "mismatch"
    else:
        actor.revision = data.revision
    actor.profile_sync_protocol = data.profile_sync_protocol if actor.os in {"linux", "windows"} else 0
    actor.profile_config_hash = data.profile_config_hash
    profile_sync.reconcile(db, actor, check_drift=True)
    for profile in db.scalars(select(Profile).where(Profile.actor_id == actor.id)):
        profile.healthy = data.profiles.get(profile.id, False)
    lease = db.get(Lease, actor.id)
    return {"accepted": True, "active_job": lease.run_id if lease else None}


@router.post("/agents/jobs/claim")
def claim_job(request: Request, actor: Actor = Depends(agent), db: Session = Depends(session)):
    if profile_sync.blocks_claim(db, actor) or (
        actor.delivery_mode != "on_demand" and catalog_deployments.blocks_claim(db, actor)
    ):
        return {"job": None}
    return {"job": claim(db, actor, request.app.state.settings)}


@router.post("/agents/jobs/{run_id}/heartbeat")
def renew(
    run_id: UUID,
    data: LeaseProof,
    request: Request,
    actor: Actor = Depends(agent),
    db: Session = Depends(session),
):
    lease = proof(db, actor, str(run_id), data.attempt_id, data.fence)
    run = need(db, Run, run_id)
    if run.status not in {"claimed", "running"}:
        fail("invalid_state", "Run is no longer active")
    if run.snapshot.get("file_plan"):
        from ..jobs.engine import authorize_waiting

        if not authorize_waiting(db, run, actor, request.app.state.settings):
            fail("authorization_expired", "Execution authorization is no longer valid")
    lease.expires_at = time.time() + request.app.state.settings.lease_seconds
    if file_plans.on_demand(run):
        attempt = db.get(Attempt, lease.attempt_id)
        if attempt is None or attempt.preparation_deadline is None:
            fail("invalid_state", "On-demand preparation record is missing")
        if not attempt.execution_authorized_at and time.time() > attempt.preparation_deadline:
            fail("preparation_expired", "Preparation deadline expired")
    elif run.status == "claimed":
        transition(db, run, "running", "agent:" + actor.id)
    return {"lease_expires_at": lease.expires_at, "cancel_requested": run.cancel_requested}


@router.post("/agents/jobs/{run_id}/result")
def submit_result(
    run_id: UUID,
    data: Result,
    request: Request,
    actor: Actor = Depends(agent),
    db: Session = Depends(session),
):
    run = need(db, Run, run_id)
    if run.actor_id != actor.id:
        fail("wrong_actor", "Job belongs to a different actor", 403)
    result(db, actor, run, data, request.app.state.settings)
    return {"accepted": True, "status": run.status}
