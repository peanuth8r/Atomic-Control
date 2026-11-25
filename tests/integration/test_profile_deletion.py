"""Profile deletion preserves evidence and serializes against work/configuration."""

import pytest
from sqlalchemy import select

from apps.api.app.models import Actor, Audit, Profile, Run
from apps.api.app.services.profile_sync import queue

ADMIN = {"X-Test-User": "admin"}


def path(env):
    return f"/api/v1/actors/{env['actor']}/profiles/{env['profiles'][0]['id']}"


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_delete_cancels_waiting_preserves_history_and_releases_profile_type(env, request_job, platform):
    run = request_job().json()
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.os = platform
        if platform == "linux":
            for p in db.scalars(select(Profile)):
                p.account = "root" if p.privilege == "elevated" else "atomic-user"
                p.expected_sid = "uid:0" if p.privilege == "elevated" else "uid:1001"
                p.logon_type = "systemd"
    response = env["client"].delete(path(env), headers=ADMIN)
    assert response.status_code == 200, response.text
    assert response.json()["cancelled_requests"] == 1
    assert env["client"].delete(path(env), headers=ADMIN).json() == response.json()
    saved = env["client"].get(f"/api/v1/runs/{run['run_id']}").json()
    assert saved["status"] == "cancelled" and saved["snapshot"] == run["snapshot"]
    assert len(env["client"].get(f"/api/v1/actors/{env['actor']}/profiles").json()) == 1
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/profiles",
        headers=ADMIN,
        json={
            "profile_key": "standard-user",
            "display_name": "Replacement",
            "account": "atomic-new",
            "expected_sid": "uid:1002" if platform == "linux" else "S-1-5-21-111-222-333-1003",
            "privilege": "standard",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["id"] != env["profiles"][0]["id"]
    with env["app"].state.sessions() as db:
        assert db.scalar(select(Audit).where(Audit.action == "profile.deleted"))


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_only_administrators_delete_profiles(env, role):
    assert env["client"].delete(path(env), headers={"X-Test-User": role}).status_code == 403


def test_profile_from_another_actor_cannot_be_deleted(env):
    from uuid import uuid4

    other = str(uuid4())
    with env["app"].state.sessions() as db, db.begin():
        db.add(Actor(id=other, hostname="other", os="windows"))
    wrong = f"/api/v1/actors/{other}/profiles/{env['profiles'][0]['id']}"
    assert env["client"].delete(wrong, headers=ADMIN).status_code == 404


@pytest.mark.parametrize("state", ["running", "inconclusive", "applying"])
def test_delete_blocks_active_or_uncertain_work_and_profile_updates(env, request_job, state):
    run = request_job().json()
    with env["app"].state.sessions() as db, db.begin():
        if state == "applying":
            queue(db, db.get(Actor, env["actor"]), "fixture").status = "applying"
        else:
            db.get(Run, run["run_id"]).status = state
    response = env["client"].delete(path(env), headers=ADMIN)
    assert response.status_code == 409, response.text
    with env["app"].state.sessions() as db:
        assert db.get(Profile, env["profiles"][0]["id"])
