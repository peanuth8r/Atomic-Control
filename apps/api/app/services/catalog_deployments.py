"""Catalog installation state and content binding for enrolled Linux actors."""

from sqlalchemy import select

from apps.agent.catalog_config import SOURCE, CatalogConfig, fingerprint

from ..catalog.parser import valid_review
from ..catalog.validation import pinned
from ..errors import fail
from ..models import AtomicTest, CatalogDeployment, CustomTestSubmission, Revision, TestApproval
from .actor_status import require_current_actor
from .common import audit


def latest(db, actor):
    return db.scalar(
        select(CatalogDeployment)
        .where(CatalogDeployment.actor_id == actor.id)
        .order_by(CatalogDeployment.generation.desc())
        .limit(1)
    )


def desired(db, actor, revision):
    if db.scalar(select(CustomTestSubmission.id).where(CustomTestSubmission.revision == revision)):
        fail("custom_test_delivery", "Custom test revisions use on-demand delivery, not a Git checkout", 422)
    if not pinned(revision) or not db.get(Revision, revision):
        fail("unknown_catalog_revision", "Select an imported pinned catalog revision", 422)
    tests = db.scalars(
        select(AtomicTest)
        .where(AtomicTest.revision == revision, AtomicTest.active.is_(True), AtomicTest.simulated.is_(False))
        .order_by(AtomicTest.guid)
    ).all()
    if not tests:
        fail("empty_catalog", "This revision has no active imported definitions", 422)
    value = CatalogConfig.model_validate(
        {
            "protocol": 1,
            "actor_id": actor.id,
            "hostname": actor.hostname,
            "os": actor.os,
            "source": SOURCE,
            "revision": revision,
            "tests": [{"guid": t.guid, "technique": t.technique, "sha256": t.content_hash} for t in tests],
        }
    ).model_dump()
    return value, tests


def options(db, actor):
    result = []
    for revision in db.scalars(select(Revision).order_by(Revision.imported_at.desc())):
        if db.scalar(select(CustomTestSubmission.id).where(CustomTestSubmission.revision == revision.id)):
            continue
        if not pinned(revision.id):
            continue
        if not db.scalar(
            select(AtomicTest.guid)
            .where(
                AtomicTest.revision == revision.id,
                AtomicTest.active.is_(True),
                AtomicTest.simulated.is_(False),
            )
            .limit(1)
        ):
            continue
        value, tests = desired(db, actor, revision.id)
        reviews = {
            r.guid: r
            for r in db.scalars(select(TestApproval).where(TestApproval.guid.in_([t.guid for t in tests])))
        }
        result.append(
            {
                "revision": revision.id,
                "manifest_hash": fingerprint(value),
                "tests": len(tests),
                "approved_tests": sum(bool(valid_review(t, reviews.get(t.guid))) for t in tests),
                "imported_at": revision.imported_at,
            }
        )
    return result


def queue(db, actor, revision, expected_hash, identity):
    require_current_actor(actor)
    value, tests = desired(db, actor, revision)
    hashed = fingerprint(value)
    if hashed != expected_hash:
        fail(
            "catalog_changed", "Imported catalog changed. Reload and review the selected revision again", 409
        )
    previous = latest(db, actor)
    if previous and previous.status in {"pending", "applying"}:
        if previous.payload_hash == hashed:
            return previous
        fail("catalog_busy", "Finish the current catalog installation before selecting another revision", 409)
    item = CatalogDeployment(
        actor_id=actor.id,
        generation=previous.generation + 1 if previous else 1,
        revision=revision,
        payload=value,
        payload_hash=hashed,
        requested_by=identity,
    )
    db.add(item)
    db.flush()
    audit(
        db,
        identity,
        "catalog_deployment.requested",
        actor.id,
        generation=item.generation,
        revision=revision,
        definitions=len(tests),
        payload_hash=hashed,
    )
    return item


def blocks_claim(db, actor):
    item = latest(db, actor)
    return bool(item and item.status in {"pending", "applying", "failed"})


def applying(db, actor):
    item = latest(db, actor)
    return bool(item and item.status == "applying")


def view(db, actor):
    item = latest(db, actor)
    return {
        "protocol": actor.catalog_sync_protocol,
        "health": actor.catalog_health,
        "status": item.status if item else "not_configured",
        "desired_revision": item.revision if item else "",
        "observed_revision": actor.revision,
        "generation": item.generation if item else 0,
        "error": item.error if item else "",
        "updated_at": item.updated_at if item else None,
    }
