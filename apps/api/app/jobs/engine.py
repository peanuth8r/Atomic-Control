import secrets
import time
from pathlib import Path

import jwt
from sqlalchemy import select

from ..catalog.parser import approved, execution_platforms
from ..errors import fail
from ..models import Actor, AtomicTest, Attempt, Lease, Log, Profile, Run, RunApproval
from ..schemas import LinuxIdentity, Result
from ..services.actor_status import require_current_actor
from ..services.catalog_deployments import blocks_claim as catalog_pending
from ..services.common import fingerprint, redact, transition
from ..services.token_time import token_issued_at

TERMINAL = {"preparation_failed", "succeeded", "failed", "timed_out", "cancelled", "inconclusive", "rejected"}


def online(actor: Actor, settings) -> bool:
    return (
        actor.enabled
        and not actor.workspace_residue
        and actor.registration_state != "retired"
        and actor.health == "healthy"
        and actor.last_heartbeat > time.time() - settings.heartbeat_threshold
    )


def eligibility(db, test, actor, profile, settings, review_override=None):
    if actor:
        require_current_actor(actor)
    if not actor or not actor.enabled:
        fail("actor_unavailable", "Actor is not registered or is disabled")
    if actor.delivery_mode != "on_demand" and catalog_pending(db, actor):
        fail(
            "catalog_update_pending",
            "Finish or retry the actor's catalog installation before requesting tests",
            409,
        )
    if not online(actor, settings):
        fail("actor_offline", "Actor is offline or unhealthy")
    if not profile or profile.actor_id != actor.id or not profile.enabled or not profile.healthy:
        fail("profile_unavailable", "Select a healthy provisioned profile for this actor")
    if test is None or not (review := review_override or approved(db, test)):
        fail("test_unapproved", "Atomic definition is not approved")
    if getattr(test, "catalog_source", "") == "custom" and actor.delivery_mode != "on_demand":
        fail("custom_test_delivery", "Custom tests require an on-demand actor")
    if profile.profile_key not in review.allowed_profiles or actor.os not in review.allowed_platforms:
        fail("incompatible_profile", "Test is not approved for this platform and profile")
    if actor.os not in execution_platforms(test.definition):
        fail("executor_unapproved", "Executor is unsupported")
    if (
        test.definition.get("executor", {}).get("elevation_required", False)
        and profile.privilege != "elevated"
    ):
        fail("elevation_required", "Test requires an approved elevated profile")
    if actor.delivery_mode == "on_demand":
        from ..services.file_plans import inherit_inline_approval
        from ..services.test_artifacts import require_artifact

        if actor.artifact_protocol != 1:
            fail("artifact_protocol_required", "Update the agent for on-demand delivery")
        if not getattr(review, "plan_hash", "") and not review.artifact:
            inherit_inline_approval(db, test, review)
        if getattr(review, "plan_hash", ""):
            from ..services.file_plans import require_plan

            require_plan(db, test, review)
        else:
            require_artifact(db, test, review)
    elif actor.revision != test.revision:
        fail("catalog_mismatch", "Actor catalog revision differs from approved definition")
    if test.simulated or actor.simulated:
        fail("mode_mismatch", "Legacy fixture resources cannot execute")
    return review


def snapshot(test, actor, profile, action, timeout, review):
    return {
        **(
            (
                {"file_plan": {"hash": review.plan_hash, "packaging_version": 1}}
                if getattr(review, "plan_hash", "")
                else {"artifact": review.artifact}
            )
            if actor.delivery_mode == "on_demand"
            else {}
        ),
        "atomic_guid": test.guid,
        "technique": test.technique,
        "test_name": test.name,
        "definition": test.definition,
        "content_sha256": test.content_hash,
        "source_revision": test.revision,
        "actor_id": actor.id,
        "actor_os": actor.os,
        "hostname": actor.hostname,
        "execution_profile_id": profile.id,
        "profile_key": profile.profile_key,
        "account": profile.account,
        "expected_sid": profile.expected_sid,
        "privilege": profile.privilege,
        "action": action,
        "timeout_seconds": timeout,
        "input_values": {k: v.get("default") for k, v in test.definition.get("input_arguments", {}).items()},
        "risk_level": review.risk_level,
        "simulated": actor.simulated,
    }


def reap(db):
    for lease in db.scalars(select(Lease).where(Lease.expires_at <= time.time())).all():
        run = db.get(Run, lease.run_id)
        if run.status not in TERMINAL:
            transition(db, run, "inconclusive", "system:lease-expired")
        # Retain the actor lock until explicit reconciliation. Never requeue.


def claim(db, actor: Actor, settings):
    # Actor is locked by authentication; all SQLite transactions use BEGIN IMMEDIATE.
    reap(db)
    if not online(actor, settings):
        fail("actor_offline", "Heartbeat required before claiming")
    if db.get(Lease, actor.id):
        return None
    if db.scalar(
        select(Run.id)
        .where(Run.actor_id == actor.id, Run.status == "inconclusive", Run.reconciled.is_(False))
        .limit(1)
    ):
        return None
    for run in db.scalars(
        select(Run)
        .where(
            Run.actor_id == actor.id,
            Run.status.in_(["queued", "preparing", "pending_approval"]),
        )
        .order_by(Run.queue_position, Run.created_at, Run.id)
    ).all():
        from ..services.run_batches import prepare_dispatch

        if run.status == "pending_approval" and not run.batch_id:
            if run.snapshot.get("file_plan"):
                return None
            continue
        if run.status not in {"queued", "preparing", "pending_approval"}:
            continue
        readiness = prepare_dispatch(db, run, actor, settings)
        if readiness == "wait":
            return None
        if readiness == "skip" or run.status not in {"queued", "preparing"}:
            continue
        if run.snapshot.get("file_plan"):
            if not authorize_waiting(db, run, actor, settings):
                return None
            from ..services.file_plans import ensure_ready

            if not ensure_ready(db, run):
                return None
        else:
            approval = db.get(RunApproval, run.id)
            if (
                not approval
                or approval.decision != "approved"
                or approval.expires_at <= time.time()
                or approval.snapshot_hash != fingerprint(run.snapshot)
            ):
                transition(db, run, "rejected", "system:approval-expired")
                continue
            test, review = run_context(db, run)
            profile = db.get(Profile, run.profile_id)
            eligibility(db, test, actor, profile, settings, review)
            current = context_snapshot(run, test, actor, profile, review)
            if fingerprint(current) != run.snapshot_hash:
                transition(db, run, "rejected", "system:approval-invalidated")
                continue
        approval = db.get(RunApproval, run.id)
        from ..services.file_plans import execution_snapshot, on_demand

        dispatched = execution_snapshot(db, run)
        dispatched_hash = fingerprint(dispatched)
        artifact = on_demand(run)
        attempt = Attempt(
            run_id=run.id,
            workspace_status="preparing" if artifact else "not_required",
            preparation_deadline=time.time() + settings.artifact_preparation_seconds if artifact else None,
        )
        db.add(attempt)
        db.flush()
        lease = Lease(
            actor_id=actor.id,
            run_id=run.id,
            attempt_id=attempt.id,
            fence=secrets.token_hex(32),
            expires_at=time.time() + settings.lease_seconds,
        )
        db.add(lease)
        transition(db, run, "claimed", "agent:" + actor.id)
        job = {
            "run_id": run.id,
            "attempt_id": attempt.id,
            "fence": lease.fence,
            "lease_expires_at": lease.expires_at,
            "snapshot_hash": dispatched_hash,
            "snapshot": dispatched,
            "approved_snapshot_hash": run.snapshot_hash,
        }
        claims = {
            **job,
            **({"purpose": "artifact-prepare-v1"} if artifact else {}),
            "iss": "atomic-control",
            "aud": actor.id,
            "iat": token_issued_at(),
            "exp": int(min(approval.expires_at, lease.expires_at)),
        }
        job["grant"] = jwt.encode(claims, Path(settings.signing_key_file).read_text(), algorithm="RS256")
        if artifact:
            # A bounded header credential; the complete signed snapshot stays in the JSON assignment.
            job["download_grant"] = jwt.encode(
                {
                    "purpose": "artifact-download-v1",
                    "iss": "atomic-control",
                    "aud": actor.id,
                    "iat": token_issued_at(),
                    "exp": int(min(approval.expires_at, attempt.preparation_deadline)),
                    "run_id": run.id,
                    "attempt_id": attempt.id,
                    "fence": lease.fence,
                    "snapshot_hash": dispatched_hash,
                    "artifact_digest": dispatched["artifact"]["digest"],
                },
                Path(settings.signing_key_file).read_text(),
                algorithm="RS256",
            )
        return job
    return None


def proof(db, actor, run_id, attempt_id, fence, allow_expired=False):
    lease = db.get(Lease, actor.id)
    if (
        not lease
        or lease.run_id != run_id
        or lease.attempt_id != str(attempt_id)
        or not secrets.compare_digest(lease.fence, fence)
    ):
        fail("stale_lease", "Job ownership or fencing proof is invalid")
    if lease.expires_at <= time.time() and not allow_expired:
        fail("lease_expired", "Lease expired; outcome requires reconciliation")
    return lease


def result(db, actor, run: Run, payload: Result, settings):
    attempt = db.get(Attempt, str(payload.attempt_id))
    value = payload.model_dump(mode="json")
    value_hash = fingerprint(value)
    if attempt and attempt.run_id == run.id and actor.id == run.actor_id and attempt.result_hash:
        if attempt.result_hash == value_hash:
            return
        fail("result_conflict", "An immutable result already exists")
    lease = proof(
        db,
        actor,
        run.id,
        payload.attempt_id,
        payload.fence,
        bool(run.snapshot.get("artifact") or run.snapshot.get("file_plan")),
    )
    if run.status not in (
        {"claimed", "running", "inconclusive"}
        if (run.snapshot.get("artifact") or run.snapshot.get("file_plan"))
        else {"claimed", "running"}
    ):
        fail("invalid_state", "Run cannot accept results")
    if payload.simulated or actor.simulated:
        fail("mode_mismatch", "Only results from real execution are accepted")
    identity = payload.identity
    s = run.snapshot
    valid_identity = bool(
        not isinstance(identity, LinuxIdentity)
        and s.get("actor_os", "windows") == "windows"
        and identity
        and identity.verified
        and str(identity.expected_profile_id) == run.profile_id
        and identity.expected_account_sid == s["expected_sid"]
        and identity.actual_account_sid == s["expected_sid"]
        and (
            identity.elevated
            and identity.admin_member
            and identity.admin_enabled
            and identity.integrity_level == "high"
            if s["privilege"] == "elevated"
            else not identity.elevated and not identity.admin_member and identity.integrity_level == "medium"
        )
    )
    if isinstance(identity, LinuxIdentity):
        expected = s["expected_sid"]
        root = s["privilege"] == "elevated"
        valid_identity = bool(
            s.get("actor_os") == "linux"
            and identity.verified
            and str(identity.expected_profile_id) == run.profile_id
            and identity.expected_account_sid == expected == identity.actual_account_sid
            and expected == f"uid:{identity.uid}"
            and identity.uid == identity.euid
            and identity.gid == identity.egid
            and identity.actual_account_name == s["account"]
            and identity.elevated == root
            and (
                identity.uid == 0 and identity.gid == 0
                if root
                else identity.uid > 0
                and identity.gid > 0
                and 0 not in identity.groups
                and identity.no_new_privileges
                and all(
                    int(value, 16) == 0
                    for value in [
                        identity.capabilities,
                        identity.permitted_capabilities,
                        identity.ambient_capabilities,
                        identity.bounding_capabilities,
                    ]
                )
            )
        )
    status = "inconclusive" if run.status == "inconclusive" else payload.status
    if (
        (s.get("artifact") or s.get("file_plan"))
        and not attempt.execution_authorized_at
        and status == "succeeded"
    ):
        fail("execution_not_authorized", "Attempt was never authorized to execute")
    if status == "succeeded" and (not valid_identity or payload.exit_code != 0):
        status = "failed"
    if run.cancel_requested and status == "succeeded":
        status = "inconclusive"
    if payload.finished_at < payload.started_at:
        fail("invalid_result", "Finish precedes start", 422)
    stdout, truncated_out = redact(payload.stdout, settings.log_limit)
    stderr, truncated_err = redact(payload.stderr, settings.log_limit)
    value.update(stdout=stdout, stderr=stderr, identity_verified=valid_identity)
    value.pop("fence", None)
    run.result = value
    attempt.result_hash = value_hash
    attempt.finished_at = time.time()
    db.add(Log(run_id=run.id, content=stdout + "\n" + stderr, truncated=truncated_out or truncated_err))
    transition(db, run, status, "agent:" + actor.id)
    if not (s.get("artifact") or s.get("file_plan")) or attempt.workspace_status == "purged":
        db.delete(lease)


def run_context(db, run):
    if run.action == "cleanup" and run.snapshot.get("file_plan"):
        from ..services.file_plans import historical_context

        parent = db.get(Run, run.parent_id) if run.parent_id else None
        if parent is None:
            fail("cleanup_parent_missing", "Original execution is unavailable")
        return historical_context(db, parent)
    if run.action == "cleanup" and run.snapshot.get("artifact"):
        from ..services.test_artifacts import historical_context

        return historical_context(db, run)
    test = db.get(AtomicTest, run.guid)
    return test, approved(db, test) if test else None


def context_snapshot(run, test, actor, profile, review):
    current = snapshot(test, actor, profile, run.action, run.snapshot["timeout_seconds"], review)
    # Existing queued snapshots retain their original exact-artifact format during migration.
    if (
        run.snapshot.get("artifact")
        and not run.snapshot.get("file_plan")
        and getattr(review, "artifact", None)
    ):
        current.pop("file_plan", None)
        current["artifact"] = review.artifact
    return current


def authorize_waiting(db, run, actor, settings):
    from ..auth.policy import authorize_subject_execution
    from ..models import UserAccessState

    if run.cancel_requested:
        transition(db, run, "cancelled", "system:preparation")
        return False
    test, review = run_context(db, run)
    profile = db.get(Profile, run.profile_id)
    review = eligibility(db, test, actor, profile, settings, review)
    access = db.get(UserAccessState, run.requested_by)
    if access and (access.blocked or access.updated_at >= run.created_at):
        fail("requester_access_changed", "Requester permissions changed; submit a new request", 403)
    authorize_subject_execution(
        settings, run.requested_by, actor, profile, test, review.risk_level, run.action
    )
    if (
        fingerprint(run.snapshot) != run.snapshot_hash
        or fingerprint(context_snapshot(run, test, actor, profile, review)) != run.snapshot_hash
    ):
        fail("approval_invalidated", "Approved definition, file plan or execution identity changed")
    approval = db.get(RunApproval, run.id)
    if (
        not approval
        or approval.decision != "approved"
        or approval.snapshot_hash != run.snapshot_hash
        or approval.authorization_source != settings.approval_mode
    ):
        fail("approval_invalidated", "Execution authorization is unavailable or changed")
    if approval.expires_at <= time.time():
        if run.status in {"claimed", "running"}:
            fail("authorization_expired", "Execution authorization expired")
        if settings.approval_mode == "catalog":
            approval.expires_at, approval.approved_by = (
                time.time() + settings.approval_seconds,
                review.approved_by,
            )
        else:
            approval.decision = "expired"
            transition(db, run, "pending_approval", "system:approval-expired")
            return False
    return True
