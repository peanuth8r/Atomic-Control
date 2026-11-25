import time

import httpx
from sqlalchemy import select

from ..errors import fail
from ..models import AtomicTest, CatalogImport, CatalogState, Revision, TestApproval
from ..services.common import audit, fingerprint
from .github import GitHubError, fetch_github
from .parser import valid_review
from .validation import pinned


def lock_catalog(db):
    state = db.get(CatalogState, 1, with_for_update=True)
    if not state:
        state = CatalogState(id=1, generation=0)
        db.add(state)
        db.flush()
    return state


def baseline(db):
    tests = list(db.scalars(select(AtomicTest)).all())
    reviews = {r.guid: r for r in db.scalars(select(TestApproval)).all()}
    values = []
    for t in tests:
        review = reviews.get(t.guid)
        values.append(
            (
                t.guid,
                t.content_hash,
                t.revision,
                t.catalog_source,
                t.active,
                [
                    review.content_hash,
                    review.revision,
                    review.allowed_profiles,
                    review.allowed_platforms,
                    review.risk_level,
                    review.approved_by,
                    review.approved,
                    review.plan_hash,
                ]
                if review
                else None,
            )
        )
    token = fingerprint(sorted(values))
    return {t.guid: t for t in tests}, reviews, token


def preview(db, staged: CatalogImport):
    existing, reviews, token = baseline(db)
    changes = []
    seen = set()
    counts = dict.fromkeys(["added", "changed", "revision_changed", "unchanged", "removed", "conflict"], 0)
    for entry in staged.definitions:
        definition = entry["definition"]
        guid = definition["auto_generated_guid"]
        seen.add(guid)
        old = existing.get(guid)
        if old and (old.catalog_source != staged.source or old.simulated):
            kind = "conflict"
        elif not old or not old.active:
            kind = "added"
        elif old.content_hash != fingerprint(definition):
            kind = "changed"
        elif old.revision != staged.revision:
            kind = "revision_changed"
        else:
            kind = "unchanged"
        counts[kind] += 1
        changes.append(
            {
                "guid": guid,
                "name": definition["name"],
                "technique": definition["technique"],
                "kind": kind,
                "path": entry["path"],
                "before": old.definition if old else None,
                "after": definition,
                "previously_approved": bool(old and valid_review(old, reviews.get(old.guid))),
            }
        )
    # A GitHub sync replaces only the GitHub source. YAML uploads always merge.
    if staged.source == "github":
        for old in existing.values():
            if old.catalog_source == "github" and old.active and old.guid not in seen:
                counts["removed"] += 1
                changes.append(
                    {
                        "guid": old.guid,
                        "name": old.name,
                        "technique": old.technique,
                        "kind": "removed",
                        "path": old.source_path,
                        "before": old.definition,
                        "after": None,
                        "previously_approved": bool(valid_review(old, reviews.get(old.guid))),
                    }
                )
    changes.sort(key=lambda c: (c["kind"] == "unchanged", c["technique"], c["name"]))
    token = fingerprint(
        {
            "baseline": token,
            "import_id": staged.id,
            "source": staged.source,
            "revision": staged.revision,
            "definitions": staged.definitions,
        }
    )
    return counts, changes, token


def status_view(staged: CatalogImport):
    if staged.status == "fetching" and staged.updated_at < time.time() - 900:
        staged.status, staged.error = (
            "failed",
            "Sync was interrupted or exceeded its time limit. Start a new sync.",
        )
    return {
        "id": staged.id,
        "source": staged.source,
        "ref": staged.ref,
        "revision": staged.revision,
        "status": staged.status,
        "created_by": staged.created_by,
        "created_at": staged.created_at,
        "updated_at": staged.updated_at,
        "applied_by": staged.applied_by,
        "error": staged.error,
        "test_count": len(staged.definitions),
        "file_count": len(staged.files),
        "pinned": pinned(staged.revision),
    }


def fetch_stage(sessions, import_id: str, token: str):
    try:
        with sessions() as db:
            staged = db.get(CatalogImport, import_id)
            if not staged or staged.status != "fetching":
                return
            ref = staged.ref
        revision, definitions, files = fetch_github(ref, token)
        with sessions() as db, db.begin():
            staged = db.get(CatalogImport, import_id, with_for_update=True)
            if staged.status != "fetching":
                return
            staged.revision, staged.definitions, staged.files = revision, definitions, files
            staged.status, staged.updated_at = "ready", time.time()
            audit(
                db,
                staged.created_by,
                "catalog.sync-staged",
                staged.id,
                revision=revision,
                count=len(definitions),
            )
    except Exception as exc:
        if isinstance(exc, GitHubError):
            message = str(exc)
        elif isinstance(exc, httpx.HTTPError):
            message = "GitHub connection failed. Check server connectivity and retry."
        else:
            message = "Catalog sync failed validation. No catalog changes were applied."
        with sessions() as db, db.begin():
            staged = db.get(CatalogImport, import_id)
            if staged and staged.status == "fetching":
                staged.status, staged.error, staged.updated_at = "failed", message, time.time()
                audit(db, staged.created_by, "catalog.sync-failed", staged.id)


def apply_stage(db, staged: CatalogImport, token: str, subject: str, replace_conflicts: bool = False):
    if staged.status == "imported":
        return  # Idempotent confirmation after a lost response.
    if staged.status != "ready":
        fail("import_not_ready", "Wait for a valid import preview before confirming")
    if staged.created_at < time.time() - 86400:
        fail("import_expired", "Preview expired. Stage the source again")
    state = lock_catalog(db)
    counts, changes, current_token = preview(db, staged)
    if token != current_token:
        fail("preview_stale", "Catalog or approvals changed. Refresh the preview and review again")
    if counts["conflict"] and not replace_conflicts:
        fail("catalog_conflict", "Explicit confirmation is required to replace GUIDs from another source")
    # Historical fixture GUIDs remain quarantined.
    if any(c["kind"] == "conflict" and db.get(AtomicTest, c["guid"]).simulated for c in changes):
        fail("legacy_fixture_conflict", "Historical fixture GUIDs cannot be replaced by imported tests")
    if not db.get(Revision, staged.revision):
        db.add(Revision(id=staged.revision))
        db.flush()
    for change in changes:
        if change["kind"] == "unchanged":
            continue
        old = db.get(AtomicTest, change["guid"])
        if change["kind"] == "removed":
            old.active = False
        else:
            if old is None:
                old = AtomicTest(guid=change["guid"])
                db.add(old)
            definition = change["after"]
            old.technique, old.name = definition["technique"], definition["name"]
            old.revision, old.content_hash = staged.revision, fingerprint(definition)
            old.definition, old.simulated, old.active = definition, False, True
            old.catalog_source, old.source_path = staged.source, change["path"]
        approval = db.get(TestApproval, change["guid"])
        if approval:
            approval.approved = False
    state.generation += 1
    staged.status, staged.updated_at, staged.applied_by = "imported", time.time(), subject
    audit(
        db,
        subject,
        "catalog.import-confirmed",
        staged.id,
        source=staged.source,
        revision=staged.revision,
        changes=counts,
    )
