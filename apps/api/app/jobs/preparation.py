"""Durable, shared central packaging. This worker never invokes an Atomic command."""

import logging
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
from fastapi import HTTPException
from sqlalchemy import func, or_, select, text

from apps.agent.artifacts import make_archive, sha256, validate_manifest

from ..models import Actor, ArtifactBuild, FilePlan, Lease, Run, SourceBlob, TestArtifact
from ..services.common import audit, fingerprint, transition
from ..services.file_plans import definition_yaml, ensure_ready, plan_key
from ..services.run_batches import pause, prepare_dispatch
from ..services.test_artifacts import fetch_assets
from .engine import TERMINAL, authorize_waiting, online

logger = logging.getLogger("atomic.preparation")


class IntegrityFailure(ValueError):
    pass


@contextmanager
def transaction(sessions):
    with sessions() as db:
        if db.bind.dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise


def reject(db, run, code, message, integrity=False):
    run.preparation_code, run.preparation_error = code, message[:512]
    transition(db, run, "rejected" if integrity else "preparation_failed", "system:preparation:" + code)
    if integrity and run.batch_id:
        from ..models import RunBatch

        pause(db, db.get(RunBatch, run.batch_id), code, run.id)


def schedule_heads(db, settings):
    """Only each actor's FIFO head can request packaging. No actor lease is acquired."""
    pending = set()
    seen = set()
    uncertain = set(
        db.scalars(select(Run.actor_id).where(Run.status == "inconclusive", Run.reconciled.is_(False)))
    )
    heads = (
        select(
            Run.id.label("run_id"),
            func.row_number()
            .over(partition_by=Run.actor_id, order_by=(Run.queue_position, Run.created_at, Run.id))
            .label("position"),
        )
        .where(
            Run.status.not_in(TERMINAL),
            or_(
                Run.status != "pending_approval",
                Run.batch_id.is_not(None),
                Run.snapshot["file_plan"]["hash"].as_string().is_not(None),
            ),
        )
        .subquery()
    )
    for run in db.scalars(
        select(Run)
        .join(heads, heads.c.run_id == Run.id)
        .where(heads.c.position == 1)
        .order_by(Run.queue_position, Run.created_at, Run.id)
    ):
        if run.actor_id in seen:
            continue
        seen.add(run.actor_id)
        if not run.snapshot.get("file_plan") or run.status not in {"queued", "preparing"}:
            continue
        actor = db.get(Actor, run.actor_id)
        if (
            not actor
            or not online(actor, settings)
            or run.actor_id in uncertain
            or db.get(Lease, run.actor_id)
        ):
            continue
        try:
            if prepare_dispatch(db, run, actor, settings) != "ready":
                continue
            if not authorize_waiting(db, run, actor, settings):
                continue
            if ensure_ready(db, run):
                continue
        except HTTPException as error:
            detail = (
                error.detail
                if isinstance(error.detail, dict)
                else {"code": "authorization_changed", "message": str(error.detail)}
            )
            reject(db, run, detail["code"], detail["message"], integrity=True)
            continue
        build = db.get(ArtifactBuild, run.snapshot["file_plan"]["hash"])
        if build.status == "failed":
            reject(
                db,
                run,
                build.error_code,
                build.error,
                integrity=build.error_code == "artifact_integrity_failed",
            )
        else:
            pending.add(build.plan_hash)
    return pending


def acquire(sessions, settings):
    with transaction(sessions) as db:
        pending = schedule_heads(db, settings)
        db.flush()
        now = time.time()
        for key in sorted(pending):
            build = db.get(ArtifactBuild, key, with_for_update=True)
            if build.status == "building" and build.lease_expires_at > now:
                continue
            if build.status not in {"pending", "retrying", "building"} or build.retry_at > now:
                continue
            if build.attempts >= 3 or (build.deadline and build.deadline <= now):
                build.status, build.error_code, build.error = (
                    "failed",
                    "preparation_timeout",
                    "Packaging could not complete before its retry/deadline limit",
                )
                continue
            build.owner, build.status = str(uuid4()), "building"
            build.attempts += 1
            build.deadline = build.deadline or now + settings.artifact_build_seconds
            build.lease_expires_at = min(now + 30, build.deadline)
            build.updated_at = now
            audit(db, "system:preparation", "artifact.build-started", key, attempt=build.attempts)
            return key, build.owner, build.deadline
    return None


def content(sessions, key, settings):
    with sessions() as db:
        plan = db.get(FilePlan, key)
        if not plan or plan.revoked or plan_key(plan.manifest) != key:
            raise IntegrityFailure("File plan is unavailable or changed")
        manifest = validate_manifest(plan.manifest)
        source, revision, definition = plan.source, plan.revision, plan.definition
        files = {}
        missing = set()
        for entry in manifest["files"]:
            blob = db.get(SourceBlob, entry["sha256"])
            if blob:
                files[entry["path"]] = blob.content
            elif entry["path"] == f"atomics/{definition['technique']}/{definition['technique']}.yaml":
                raw = definition_yaml(definition)
                if len(raw) != entry["size"] or sha256(raw) != entry["sha256"]:
                    # Historical plans may pin the pre-fix representation. It is
                    # recoverable only when it matches the exact approved hash.
                    raw = definition_yaml(definition, legacy=True)
                files[entry["path"]] = raw
            else:
                missing.add(entry["path"])
    if missing:
        if source != "github":
            raise OSError("Retained custom supporting files are unavailable")
        files.update(fetch_assets(revision, missing, settings.github_token.get_secret_value()))
    for entry in manifest["files"]:
        value = files.get(entry["path"])
        if value is None or len(value) != entry["size"] or sha256(value) != entry["sha256"]:
            raise IntegrityFailure("Supporting file content differs from its approval")
    return manifest, definition, make_archive(files, manifest)


def process_once(sessions, settings, stop=None, tick=None):
    stop = stop or threading.Event()
    assignment = acquire(sessions, settings)
    if tick:
        tick()
    if not assignment:
        return False
    key, owner, deadline = assignment
    finished = threading.Event()
    lost = threading.Event()

    def renewal():
        while not finished.wait(5):
            try:
                with transaction(sessions) as db:
                    build = db.get(ArtifactBuild, key, with_for_update=True)
                    if (
                        build.owner != owner
                        or build.status != "building"
                        or time.time() >= deadline
                        or stop.is_set()
                    ):
                        lost.set()
                        return
                    build.lease_expires_at = min(time.time() + 30, deadline)
                    build.updated_at = time.time()
                if tick:
                    tick()
            except Exception:
                lost.set()
                return

    thread = threading.Thread(target=renewal, daemon=True)
    thread.start()
    try:
        manifest, definition, archive = content(sessions, key, settings)
        if stop.is_set() or lost.is_set() or time.time() >= deadline:
            raise TimeoutError("Packaging was interrupted or exceeded its deadline")
        digest = sha256(archive)
        signature = jwt.encode(
            {
                "iss": "atomic-control",
                "aud": "atomic-control-artifact",
                "purpose": "artifact-manifest-v1",
                "manifest": manifest,
            },
            Path(settings.signing_key_file).read_text(),
            algorithm="RS256",
        )
        descriptor = {
            "protocol": 1,
            "digest": digest,
            "size": len(archive),
            "manifest_hash": fingerprint(manifest),
            "manifest": manifest,
            "signature": signature,
        }
        with transaction(sessions) as db:
            build = db.get(ArtifactBuild, key, with_for_update=True)
            plan = db.get(FilePlan, key)
            if (
                build.owner != owner
                or build.status != "building"
                or build.lease_expires_at <= time.time()
                or lost.is_set()
            ):
                return False  # A reclaimed worker can never publish over the new owner.
            if plan.revoked:
                raise IntegrityFailure("Approval was revoked during packaging")
            item = db.get(TestArtifact, digest)
            if item is None:
                item = TestArtifact(
                    digest=digest,
                    guid=plan.guid,
                    revision=plan.revision,
                    definition=definition,
                    descriptor=descriptor,
                    archive=archive,
                    approval=plan.approval,
                    revoked=False,
                )
                db.add(item)
            elif item.descriptor["manifest"] != manifest:
                raise IntegrityFailure("Immutable artifact digest collision")
            else:
                item.revoked, item.approval = False, plan.approval
            build.status, build.artifact_digest, build.error, build.error_code = "ready", digest, "", ""
            build.owner, build.lease_expires_at, build.updated_at = "", 0, time.time()
            audit(db, "system:preparation", "artifact.build-ready", key, digest=digest)
        return True
    except Exception as error:
        integrity = isinstance(error, IntegrityFailure)
        # Never expose exception text from URLs, local files or credentials in UI errors.
        message = (
            "Packaged files do not match their approval; review the test before execution"
            if integrity
            else "Test packaging could not complete. Check central source storage/connectivity and retry"
        )
        with transaction(sessions) as db:
            build = db.get(ArtifactBuild, key, with_for_update=True)
            if build.owner == owner and build.status == "building":
                final = integrity or build.attempts >= 3 or time.time() >= deadline
                build.status = "failed" if final else "retrying"
                build.retry_at = time.time() + min(30, 2**build.attempts)
                build.owner, build.lease_expires_at = "", 0
                build.error_code = "artifact_integrity_failed" if integrity else "preparation_unavailable"
                build.error, build.updated_at = message, time.time()
                audit(db, "system:preparation", "artifact.build-" + build.status, key, code=build.error_code)
        if not isinstance(error, (OSError, ValueError, httpx.HTTPError)):
            logger.error("artifact_build_failed error_type=%s", type(error).__name__)
        return False
    finally:
        finished.set()
        thread.join(timeout=5)
        if tick:
            tick()


def worker(sessions, settings, stop, tick=None):
    while not stop.is_set():
        try:
            process_once(sessions, settings, stop, tick)
        except Exception as error:
            logger.error("preparation_worker_error error_type=%s", type(error).__name__)
        stop.wait(1)
