"""Human artifact preparation and machine-bound delivery; no anonymous asset URLs."""

import secrets
import time
from pathlib import Path
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import Principal, agent, human, viewer
from ..db import session
from ..errors import fail
from ..jobs.engine import authorize_waiting, context_snapshot, eligibility, proof, run_context
from ..models import Actor, AtomicTest, Attempt, Lease, Profile, Run, RunApproval, TestArtifact
from ..schemas import ArtifactPreparation, LeaseProof, WorkspaceReceipt
from ..services.common import audit, fingerprint, transition
from ..services.file_plans import execution_snapshot, on_demand
from ..services.test_artifacts import artifact_for, prepare, suggested_assets
from ..services.token_time import token_issued_at

router = APIRouter(prefix="/api/v1", tags=["On-demand artifacts"])


def need(db, model, key):
    item = db.get(model, str(key))
    if not item:
        fail("not_found", "Resource does not exist", 404)
    return item


@router.get("/tests/{guid}/artifact")
def artifact_details(guid: UUID, db: Session = Depends(session), p: Principal = Depends(viewer)):
    test = need(db, AtomicTest, guid)
    error = ""
    try:
        paths = suggested_assets(test.definition)
    except ValueError as exc:
        paths, error = [], str(exc)
    item = artifact_for(db, test)
    from ..models import TestApproval
    from ..services.custom_tests import submitted_files
    from ..services.file_plans import plan_view, valid_plan

    plan = valid_plan(db, test, db.get(TestApproval, test.guid))
    submitted = submitted_files(db, test)
    return {
        "file_plan": plan_view(plan) if plan else None,
        "artifact": item.descriptor if item else None,
        "suggested_assets": sorted(set(paths) | {entry["path"] for entry in submitted}),
        "submitted_files": submitted,
        "error": error,
    }


@router.post("/tests/{guid}/artifact/prepare")
def prepare_artifact(
    guid: UUID,
    data: ArtifactPreparation,
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    p.require("administrator")
    item = prepare(db, need(db, AtomicTest, guid), data, request.app.state.settings, p.subject)
    return {"artifact": item.descriptor}


def active(db, actor, run_id, attempt_id, fence, settings):
    lease = proof(db, actor, str(run_id), attempt_id, fence)
    run = need(db, Run, run_id)
    if run.actor_id != actor.id or not on_demand(run) or run.status not in {"claimed", "running"}:
        fail("invalid_state", "No active on-demand attempt")
    attempt = need(db, Attempt, lease.attempt_id)
    if not attempt.execution_authorized_at and time.time() >= attempt.preparation_deadline:
        fail("preparation_expired", "Preparation deadline expired")
    approval = db.get(RunApproval, run.id)
    if (
        run.cancel_requested
        or not approval
        or approval.decision != "approved"
        or approval.expires_at <= time.time()
        or approval.snapshot_hash != run.snapshot_hash
    ):
        fail("authorization_expired", "Job authorization was cancelled or expired")
    if run.snapshot.get("file_plan") and not authorize_waiting(db, run, actor, settings):
        fail("authorization_expired", "Execution authorization is no longer valid")
    test, review = run_context(db, run)
    profile = db.get(Profile, run.profile_id)
    eligibility(db, test, actor, profile, settings, review)
    if (
        fingerprint(run.snapshot) != run.snapshot_hash
        or fingerprint(context_snapshot(run, test, actor, profile, review)) != run.snapshot_hash
    ):
        fail("approval_invalidated", "Approved execution context changed")
    return run, attempt, lease, approval


@router.get("/agents/jobs/{run_id}/artifact")
def download(
    run_id: UUID,
    request: Request,
    x_job_grant: str = Header(),
    actor: Actor = Depends(agent),
    db: Session = Depends(session),
):
    settings = request.app.state.settings
    from ..agents.package import public_key

    try:
        claims = jwt.decode(
            x_job_grant,
            public_key(settings),
            algorithms=["RS256"],
            audience=actor.id,
            issuer="atomic-control",
            options={"require": ["exp", "iat", "aud", "iss", "purpose"]},
        )
    except jwt.PyJWTError:
        fail("invalid_grant", "Invalid preparation grant", 403)
    if claims.get("purpose") != "artifact-download-v1" or claims.get("run_id") != str(run_id):
        fail("invalid_grant", "Grant is not for this preparation", 403)
    run, attempt, lease, _ = active(
        db, actor, run_id, claims.get("attempt_id"), claims.get("fence", ""), settings
    )
    if (
        claims.get("artifact_digest") != execution_snapshot(db, run)["artifact"]["digest"]
        or claims.get("snapshot_hash") != fingerprint(execution_snapshot(db, run))
        or attempt.execution_authorized_at
    ):
        fail("invalid_grant", "Preparation grant differs from the active job", 403)
    artifact = need(db, TestArtifact, execution_snapshot(db, run)["artifact"]["digest"])
    audit(
        db,
        "agent:" + actor.id,
        "artifact.download-authorized",
        artifact.digest,
        run_id=run.id,
        attempt_id=attempt.id,
    )
    return Response(
        artifact.archive,
        media_type="application/zip",
        headers={
            "Content-Length": str(artifact.descriptor["size"]),
            "Content-Disposition": 'attachment; filename="test-bundle.zip"',
        },
    )


@router.post("/agents/jobs/{run_id}/ready")
def ready(
    run_id: UUID,
    data: LeaseProof,
    request: Request,
    actor: Actor = Depends(agent),
    db: Session = Depends(session),
):
    settings = request.app.state.settings
    run, attempt, lease, approval = active(db, actor, run_id, data.attempt_id, data.fence, settings)
    if attempt.workspace_status in {"purged", "purge_failed"}:
        fail("invalid_state", "Workspace is no longer executable")
    attempt.workspace_status = "verified"
    attempt.execution_authorized_at = attempt.execution_authorized_at or time.time()
    transition(db, run, "running", "agent:" + actor.id)
    job = {
        "run_id": run.id,
        "attempt_id": attempt.id,
        "fence": lease.fence,
        "lease_expires_at": lease.expires_at,
        "snapshot_hash": fingerprint(execution_snapshot(db, run)),
        "snapshot": execution_snapshot(db, run),
        "approved_snapshot_hash": run.snapshot_hash,
    }
    claims = {
        **job,
        "purpose": "artifact-execute-v1",
        "iss": "atomic-control",
        "aud": actor.id,
        "iat": token_issued_at(),
        "exp": int(min(approval.expires_at, lease.expires_at)),
    }
    job["grant"] = jwt.encode(claims, Path(settings.signing_key_file).read_text(), algorithm="RS256")
    audit(
        db,
        "agent:" + actor.id,
        "artifact.execution-authorized",
        run.id,
        digest=execution_snapshot(db, run)["artifact"]["digest"],
    )
    return {"job": job}


@router.post("/agents/jobs/{run_id}/workspace")
def workspace(
    run_id: UUID, data: WorkspaceReceipt, actor: Actor = Depends(agent), db: Session = Depends(session)
):
    run = need(db, Run, run_id)
    attempt = need(db, Attempt, data.attempt_id)
    if (
        run.actor_id != actor.id
        or attempt.run_id != run.id
        or not on_demand(run)
        or execution_snapshot(db, run)["artifact"]["digest"] != data.artifact_digest
    ):
        fail("wrong_attempt", "Workspace receipt differs from the assigned attempt", 403)
    lease = db.get(Lease, actor.id)
    if not lease:
        if attempt.result_hash and attempt.workspace_status == data.status == "purged":
            return {"accepted": True}
        fail("stale_lease", "No matching attempt lease")
    if (
        lease.run_id != run.id
        or lease.attempt_id != attempt.id
        or not secrets.compare_digest(lease.fence, data.fence)
    ):
        fail("stale_lease", "Workspace receipt has stale ownership")
    if attempt.workspace_status == "purged" and data.status != "purged":
        fail("invalid_state", "Removal receipt cannot be reversed")
    attempt.workspace_status = data.status
    audit(db, "agent:" + actor.id, "artifact.workspace-" + data.status, run.id, digest=data.artifact_digest)
    if data.status == "purged" and attempt.result_hash:
        db.delete(lease)
    return {"accepted": True}
