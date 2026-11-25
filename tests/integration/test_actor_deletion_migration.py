"""Exercise the schema upgrade with real foreign-key-linked evidence in an isolated database."""

from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select

from apps.api.app.db import factory, make_engine
from apps.api.app.models import Actor, AtomicTest, Cleanup, Credential, Event, Log, Profile, Run, RunApproval
from tests.support.fixtures import seed


def test_populated_upgrade_keeps_evidence_after_actor_and_profile_deletion(env, tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/migration.db"
    monkeypatch.setenv("ATOMIC_DATABASE_URL", url)
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    command.upgrade(config, "head")
    seed(env["settings"].model_copy(update={"database_url": url}))
    engine = make_engine(url)
    parent, child = str(uuid4()), str(uuid4())
    with factory(engine)() as db, db.begin():
        actor = db.scalar(select(Actor))
        profile = db.scalar(select(Profile).where(Profile.actor_id == actor.id))
        test = db.scalar(select(AtomicTest))
        actor_id, profile_id = actor.id, profile.id
        snap = {"hostname": actor.hostname, "actor_id": actor_id, "execution_profile_id": profile_id}
        for run_id, key, parent_id in [(parent, "history", None), (child, "cleanup", parent)]:
            db.add(
                Run(
                    id=run_id,
                    guid=test.guid,
                    actor_id=actor_id,
                    profile_id=profile_id,
                    parent_id=parent_id,
                    requested_by="fixture",
                    idempotency_key=key,
                    request_hash="a" * 64,
                    reason="Migration evidence fixture",
                    action="cleanup" if parent_id else "execute",
                    status="cancelled" if parent_id else "succeeded",
                    snapshot=snap,
                    snapshot_hash="b" * 64,
                )
            )
            db.flush()
        db.add_all(
            [
                Log(run_id=parent, content="Historical execution evidence"),
                Event(run_id=parent, status="succeeded", identity="fixture"),
                RunApproval(
                    run_id=parent,
                    approved_by="fixture",
                    snapshot_hash="b" * 64,
                    expires_at=0,
                    decision="approved",
                ),
                Cleanup(id=child, parent_id=parent, status="cancelled"),
            ]
        )
    # Materialize legacy columns/constraints before exercising the populated upgrade.
    # Seeding uses current ORM models; the downgrade removes all newer queue columns.
    command.downgrade(config, "e83c195a627b")
    with engine.connect() as connection:
        assert any(
            fk["constrained_columns"] == ["actor_id"]
            for fk in inspect(connection).get_foreign_keys("execution_runs")
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert all(
            fk["constrained_columns"] not in [["actor_id"], ["profile_id"]]
            for fk in inspect(connection).get_foreign_keys("execution_runs")
        )
    with factory(engine)() as db, db.begin():
        for credential in db.scalars(select(Credential).where(Credential.actor_id == actor_id)):
            db.delete(credential)
        for profile in db.scalars(select(Profile).where(Profile.actor_id == actor_id)):
            db.delete(profile)
        db.flush()
        db.delete(db.get(Actor, actor_id))
    with factory(engine)() as db:
        assert db.get(Run, parent).actor_id == actor_id
        assert db.get(Run, parent).profile_id == profile_id
        assert db.get(Run, parent).snapshot == snap
        assert db.get(Run, child).parent_id == parent
        assert db.get(Log, parent).content == "Historical execution evidence"
        assert db.get(RunApproval, parent).approved_by == "fixture"
        assert db.get(Cleanup, child).parent_id == parent
        assert db.scalar(select(Event).where(Event.run_id == parent)).status == "succeeded"
    with pytest.raises(RuntimeError, match="pre-deletion backup"):
        command.downgrade(config, "e83c195a627b")
    engine.dispose()
