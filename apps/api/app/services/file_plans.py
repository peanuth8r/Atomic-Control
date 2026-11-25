"""Content approval independent of transport packaging, with immutable dispatch bindings."""

import base64
import tarfile
import time
from types import SimpleNamespace

import httpx
from sqlalchemy import select, text

from apps.agent.artifacts import MAX_FILE_BYTES, safe_path, sha256, validate_manifest

from ..catalog.serialization import definition_yaml
from ..errors import fail
from ..models import ArtifactBuild, ExecutionBinding, FilePlan, SourceBlob, TestArtifact, UserAccessState
from .common import audit, fingerprint, transition
from .custom_tests import retained_files, submitted_files
from .test_artifacts import fetch_assets, suggested_assets


def plan_key(manifest):
    return fingerprint({"manifest": manifest, "packaging_version": 1})


def plan_view(plan):
    return {"hash": plan.hash, "manifest": plan.manifest, "packaging_version": plan.packaging_version}


def valid_plan(db, test, review):
    plan = db.get(FilePlan, review.plan_hash) if review and getattr(review, "plan_hash", "") else None
    return (
        plan
        if plan
        and not plan.revoked
        and plan.guid == test.guid
        and plan.revision == test.revision
        and fingerprint(plan.definition) == test.content_hash
        and plan_key(plan.manifest) == plan.hash
        else None
    )


def require_plan(db, test, review):
    plan = valid_plan(db, test, review)
    if not plan:
        fail("file_plan_unapproved", "Approved test files are unavailable or have been revoked")
    return plan


def inherit_inline_approval(db, test, review):
    """Adapt a legacy definition-only approval without adding any executable content.

    No network I/O, new human approval, or changes to approved risk/platforms/identities.
    Tests with external assets continue to use their reviewed immutable file plans.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    from ..catalog.parser import valid_review

    db.refresh(review, with_for_update=True)
    if not valid_review(test, review) or review.plan_hash or review.artifact:
        return False
    try:
        if suggested_assets(test.definition):
            return False
    except ValueError as error:
        fail("file_plan_invalid", str(error), 422)
    raw = definition_yaml(test.definition)
    manifest = validate_manifest(
        {
            "protocol": 1,
            "guid": test.guid,
            "technique": test.technique,
            "revision": test.revision,
            "definition_hash": test.content_hash,
            "files": [
                {
                    "path": f"atomics/{test.technique}/{test.technique}.yaml",
                    "size": len(raw),
                    "sha256": sha256(raw),
                }
            ],
        }
    )
    key = plan_key(manifest)
    approval = {
        k: getattr(review, k)
        for k in ("allowed_profiles", "allowed_platforms", "risk_level", "approved_by", "approved")
    }
    insert = sqlite_insert if db.bind.dialect.name == "sqlite" else pg_insert
    db.execute(insert(SourceBlob).values(digest=sha256(raw), content=raw).on_conflict_do_nothing())
    db.execute(
        insert(FilePlan)
        .values(
            hash=key,
            guid=test.guid,
            revision=test.revision,
            definition=test.definition,
            manifest=manifest,
            source=test.catalog_source,
            packaging_version=1,
            approval=approval,
            revoked=False,
        )
        .on_conflict_do_nothing()
    )
    plan = db.get(FilePlan, key, populate_existing=True)
    blob = db.get(SourceBlob, sha256(raw), populate_existing=True)
    if plan.revoked or plan.manifest != manifest or plan.approval != approval or blob.content != raw:
        fail("file_plan_invalid", "Stored test files differ from the existing catalog approval")
    review.plan_hash = key
    db.flush()
    audit(
        db,
        "system:preparation",
        "file-plan.inherited-catalog-approval",
        key,
        guid=test.guid,
        catalog_approved_by=review.approved_by,
    )
    return True


def resolve_approval(db, test, data, settings, subject):
    """The one normal approval action resolves content, but never builds a ZIP."""
    started = time.time()
    if data.content_sha256 != test.content_hash or data.source_revision != test.revision:
        fail("catalog_mismatch", "Refresh the test before approving its files")
    # Reuse an already reviewed immutable plan when no dependency edits were supplied.
    from ..models import TestApproval

    previous = db.get(TestApproval, test.guid)
    if previous and previous.plan_hash and not data.files:
        existing = db.get(FilePlan, previous.plan_hash)
        raw_yaml = definition_yaml(test.definition)
        yaml_entry = {
            "path": f"atomics/{test.technique}/{test.technique}.yaml",
            "size": len(raw_yaml),
            "sha256": sha256(raw_yaml),
        }
        if (
            existing
            and existing.guid == test.guid
            and existing.revision == test.revision
            and fingerprint(existing.definition) == test.content_hash
            and plan_key(existing.manifest) == existing.hash
            # Re-approval must not reuse YAML from an older renderer. Existing
            # plans and run bindings retain their original immutable content.
            and yaml_entry in existing.manifest["files"]
            and (
                data.asset_paths is None
                or set(data.asset_paths)
                == {
                    f["path"]
                    for f in existing.manifest["files"]
                    if f["path"] != f"atomics/{test.technique}/{test.technique}.yaml"
                }
            )
        ):
            intact = True
            for entry in existing.manifest["files"]:
                blob = db.get(SourceBlob, entry["sha256"])
                if blob and (len(blob.content) != entry["size"] or sha256(blob.content) != entry["sha256"]):
                    intact = False
                    break
            if intact:
                return existing
    try:
        paths = {
            safe_path(p)
            for p in (
                data.asset_paths
                if data.asset_paths is not None
                else sorted(
                    set(suggested_assets(test.definition))
                    | {entry["path"] for entry in submitted_files(db, test)}
                )
            )
        }
        required = set(suggested_assets(test.definition))
        if not required <= paths:
            raise ValueError(
                "Supporting files omit a referenced path: " + ", ".join(sorted(required - paths))
            )
        yaml_path = f"atomics/{test.technique}/{test.technique}.yaml"
        if yaml_path in paths:
            raise ValueError("The selected test YAML is included automatically")
        supplied = {}
        for item in data.files:
            path = safe_path(item.path)
            raw = base64.b64decode(item.content_base64, validate=True)
            if path not in paths or path in supplied or len(raw) > MAX_FILE_BYTES:
                raise ValueError("Invalid supporting file")
            supplied[path] = raw
        # Retained blobs permit changing risk/profiles without re-uploading custom files.
        if previous and previous.plan_hash:
            old = db.get(FilePlan, previous.plan_hash)
            if old and old.revision == test.revision and old.definition == test.definition:
                for entry in old.manifest["files"]:
                    if entry["path"] in paths and entry["path"] not in supplied:
                        blob = db.get(SourceBlob, entry["sha256"])
                        if (
                            blob
                            and len(blob.content) == entry["size"]
                            and sha256(blob.content) == entry["sha256"]
                        ):
                            supplied[entry["path"]] = blob.content
        missing = paths - set(supplied)
        supplied.update(retained_files(db, test, missing))
        missing = paths - set(supplied)
        if missing and test.catalog_source != "github":
            raise ValueError("Attach each custom supporting file before approval")
        if test.catalog_source == "github" and data.files:
            raise ValueError("Official supporting files come only from the exact official source commit")
        # Release the API write transaction before network I/O.
        db.commit()
        files = {**supplied, **fetch_assets(test.revision, missing, settings.github_token.get_secret_value())}
        files[yaml_path] = definition_yaml(test.definition)
        manifest = validate_manifest(
            {
                "protocol": 1,
                "guid": test.guid,
                "technique": test.technique,
                "revision": test.revision,
                "definition_hash": test.content_hash,
                "files": [
                    {"path": p, "size": len(raw), "sha256": sha256(raw)} for p, raw in sorted(files.items())
                ],
            }
        )
    except (ValueError, OSError, httpx.HTTPError, tarfile.TarError) as error:
        fail(
            "file_plan_invalid",
            str(error)
            if isinstance(error, ValueError)
            else "Supporting files could not be verified; retry approval",
            422,
        )
    if db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))
    db.refresh(test, with_for_update=True)
    if not test.active or data.content_sha256 != test.content_hash or data.source_revision != test.revision:
        fail("catalog_mismatch", "The definition changed while its supporting files were being verified")
    access = db.get(UserAccessState, subject)
    if access and (access.blocked or access.updated_at >= started):
        fail("identity_changed", "Your permissions changed during review; sign in again", 403)
    key = plan_key(manifest)
    plan = db.get(FilePlan, key)
    if plan is None:
        plan = FilePlan(
            hash=key,
            guid=test.guid,
            revision=test.revision,
            definition=test.definition,
            manifest=manifest,
            source=test.catalog_source,
            packaging_version=1,
            approval={},
            revoked=True,
        )
        db.add(plan)
    for raw in files.values():
        digest = sha256(raw)
        blob = db.get(SourceBlob, digest)
        if blob is None:
            db.add(SourceBlob(digest=digest, content=raw))
            db.flush()
        elif sha256(blob.content) != digest:
            blob.content = raw
            audit(db, subject, "artifact-source.repaired", digest)
    db.flush()
    audit(db, subject, "file-plan.resolved", key, guid=test.guid, files=len(files))
    return plan


def on_demand(run):
    return bool(run.snapshot.get("artifact") or run.snapshot.get("file_plan"))


def execution_snapshot(db, run):
    if not run.snapshot.get("file_plan"):
        return run.snapshot
    binding = db.get(ExecutionBinding, run.id)
    if (
        not binding
        or binding.approved_snapshot_hash != run.snapshot_hash
        or fingerprint(run.snapshot) != run.snapshot_hash
        or fingerprint(binding.snapshot) != binding.snapshot_hash
    ):
        fail("execution_not_prepared", "This run has no sealed execution bundle")
    expected = {
        **run.snapshot,
        "artifact": binding.snapshot.get("artifact"),
        "approved_snapshot_hash": run.snapshot_hash,
    }
    if expected != binding.snapshot:
        fail("binding_mismatch", "Execution content differs from the approved snapshot")
    plan = db.get(FilePlan, binding.plan_hash)
    if not plan or binding.snapshot["artifact"]["manifest"] != plan.manifest:
        fail("binding_mismatch", "Execution manifest differs from the approved file plan")
    if binding.plan_hash != run.snapshot["file_plan"]["hash"]:
        fail("binding_mismatch", "Execution binding differs from the approved file plan")
    return binding.snapshot


def seal(db, run, artifact):
    key = run.snapshot["file_plan"]["hash"]
    plan = db.get(FilePlan, key)
    if not plan or plan.revoked or artifact.revoked or artifact.descriptor["manifest"] != plan.manifest:
        fail("artifact_mismatch", "Packaged content differs from the approved plan")
    binding = db.get(ExecutionBinding, run.id)
    if binding:
        if (
            binding.snapshot["artifact"] != artifact.descriptor
            or binding.approved_snapshot_hash != run.snapshot_hash
        ):
            fail("binding_conflict", "A different immutable execution binding already exists")
        return binding
    snap = {**run.snapshot, "artifact": artifact.descriptor, "approved_snapshot_hash": run.snapshot_hash}
    binding = ExecutionBinding(
        run_id=run.id,
        plan_hash=key,
        approved_snapshot_hash=run.snapshot_hash,
        snapshot=snap,
        snapshot_hash=fingerprint(snap),
    )
    db.add(binding)
    audit(
        db,
        "system:preparation",
        "execution.binding-sealed",
        run.id,
        artifact=artifact.digest,
        approved_snapshot_hash=run.snapshot_hash,
    )
    return binding


def ensure_ready(db, run):
    if not run.snapshot.get("file_plan"):
        return True
    if db.get(ExecutionBinding, run.id):
        execution_snapshot(db, run)
        return True
    key = run.snapshot["file_plan"]["hash"]
    build = db.get(ArtifactBuild, key)
    if build and build.status == "ready":
        artifact = db.get(TestArtifact, build.artifact_digest)
        if not artifact:
            fail("artifact_unavailable", "Prepared bundle is missing")
        seal(db, run, artifact)
        if run.status == "preparing":
            transition(db, run, "queued", "system:preparation")
        return True
    if build is None:
        db.add(ArtifactBuild(plan_hash=key))
    if run.status != "preparing":
        transition(db, run, "preparing", "system:preparation")
    return False


def historical_context(db, run):
    key = run.snapshot["file_plan"]["hash"]
    plan = db.get(FilePlan, key)
    if not plan or plan.revoked or not plan.approval:
        fail("file_plan_unapproved", "Original file approval is unavailable or revoked")
    snap = execution_snapshot(db, run)
    artifact = db.get(TestArtifact, snap["artifact"]["digest"])
    if not artifact or artifact.revoked:
        fail("artifact_unapproved", "Original bundle is unavailable or revoked")
    test = SimpleNamespace(
        guid=plan.guid,
        catalog_source=plan.source,
        technique=plan.definition["technique"],
        name=plan.definition["name"],
        revision=plan.revision,
        content_hash=fingerprint(plan.definition),
        definition=plan.definition,
        active=True,
        simulated=False,
    )
    return test, SimpleNamespace(**plan.approval, plan_hash=key, artifact=artifact.descriptor)


def preparation_view(db, run):
    if not run.snapshot.get("file_plan"):
        return {}
    build = db.get(ArtifactBuild, run.snapshot["file_plan"]["hash"])
    return {
        "status": "failed" if run.status == "preparation_failed" else build.status if build else "pending",
        "attempts": build.attempts if build else 0,
        "retry_at": build.retry_at if build else 0,
        "error": run.preparation_error or (build.error if build else ""),
        "code": run.preparation_code or (build.error_code if build else ""),
        "stalled": bool(
            build
            and (
                (build.status == "building" and build.lease_expires_at < time.time())
                or (build.status in {"pending", "retrying"} and build.updated_at < time.time() - 45)
            )
        ),
    }


def revoke_plans(db, guid):
    for plan in db.scalars(select(FilePlan).where(FilePlan.guid == guid)):
        plan.revoked = True
