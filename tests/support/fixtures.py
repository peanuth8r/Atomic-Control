"""Synthetic rows for isolated test databases only; never a deployment entry point."""

import secrets
import time
from pathlib import Path

from sqlalchemy import select

from apps.api.app.config import Settings
from apps.api.app.db import factory, make_engine
from apps.api.app.models import Actor, AtomicTest, Credential, Profile, TestApproval
from apps.api.app.services.common import audit, digest


def seed(settings: Settings):
    if "artifacts/keycloak" in settings.database_url or settings.database_url.endswith("atomic-real.db"):
        raise RuntimeError("Test fixtures cannot touch the live database")
    with factory(make_engine(settings.database_url))() as db, db.begin():
        from apps.api.app.catalog.parser import parse_file
        from apps.api.app.models import Revision
        from apps.api.app.services.common import fingerprint

        revision = "c" * 40
        if not db.get(Revision, revision):
            db.add(Revision(id=revision))
            db.flush()
        for path in Path("tests/fixtures/catalog").rglob("T*.yaml"):
            for definition in parse_file(path):
                if not db.get(AtomicTest, definition["auto_generated_guid"]):
                    db.add(
                        AtomicTest(
                            guid=definition["auto_generated_guid"],
                            technique=definition["technique"],
                            name=definition["name"],
                            definition=definition,
                            content_hash=fingerprint(definition),
                            revision=revision,
                            simulated=False,
                            active=True,
                            catalog_source="test-fixture",
                        )
                    )
        actor = db.scalar(select(Actor).where(Actor.hostname == "WIN-TEST-01"))
        if not actor:
            actor = Actor(
                hostname="WIN-TEST-01",
                simulated=False,
                revision="c" * 40,
                os_version="Windows test fixture",
                agent_version="0.1.0",
                health="healthy",
                last_heartbeat=time.time(),
            )
            db.add(actor)
            db.flush()
            for key, privilege, rid in [
                ("standard-user", "standard", "1001"),
                ("local-admin", "elevated", "1002"),
            ]:
                db.add(
                    Profile(
                        actor_id=actor.id,
                        profile_key=key,
                        display_name="Standard User" if privilege == "standard" else "Local Administrator",
                        account="WIN-TEST-01\\atomic-" + ("user" if privilege == "standard" else "admin"),
                        expected_sid="S-1-5-21-111-222-333-" + rid,
                        privilege=privilege,
                        healthy=True,
                    )
                )
        if actor.registration_state == "retired":
            raise RuntimeError("The test actor was retired; use a fresh test database")
        token = secrets.token_urlsafe(48)
        db.add(Credential(actor_id=actor.id, digest=digest(token), expires_at=time.time() + 86400))
        for test in db.scalars(
            select(AtomicTest).where(AtomicTest.catalog_source == "test-fixture", AtomicTest.active.is_(True))
        ):
            db.merge(
                TestApproval(
                    guid=test.guid,
                    content_hash=test.content_hash,
                    revision=test.revision,
                    allowed_profiles=["standard-user", "local-admin"],
                    allowed_platforms=["windows"],
                    risk_level="low",
                    approved_by="test:fixture-setup",
                    approved=True,
                )
            )
        audit(db, "test:fixture-setup", "test.seed", actor.id)
        return actor.id, token


def fixture_result(job):
    s = job["snapshot"]
    return {
        "attempt_id": job["attempt_id"],
        "fence": job["fence"],
        "status": "succeeded",
        "simulated": False,
        "exit_code": 0,
        "started_at": time.time() - 0.1,
        "finished_at": time.time(),
        "stdout": "Synthetic test evidence: no command was executed.\nAction: " + s["action"],
        "stderr": "",
        "identity": {
            "expected_profile_id": s["execution_profile_id"],
            "expected_account_sid": s["expected_sid"],
            "actual_account_sid": s["expected_sid"],
            "actual_account_name": s["account"],
            "elevated": s["privilege"] == "elevated",
            "admin_member": s["privilege"] == "elevated",
            "admin_enabled": s["privilege"] == "elevated",
            "enabled_privileges": [],
            "integrity_level": "high" if s["privilege"] == "elevated" else "medium",
            "process_id": 100,
            "logon_session_id": "test-fixture",
            "verified": True,
        },
        "prerequisites": {"status": "ready"} if s["action"] == "check" else None,
    }
