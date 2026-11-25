import time

import pytest

from apps.api.app.models import Actor, AtomicTest, Profile
from apps.api.app.services.common import fingerprint

GUID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def linux(env):
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.os, actor.os_version = "linux", "Linux simulation"
        test = db.get(AtomicTest, GUID)
        test.definition = {
            **test.definition,
            "supported_platforms": ["linux"],
            "executor": {
                "name": "bash",
                "command": "printf 'synthetic Linux fixture'",
                "cleanup_command": "printf 'synthetic cleanup'",
            },
        }
        test.content_hash = fingerprint(test.definition)
        hash_value, revision = test.content_hash, test.revision
        for p in db.query(Profile).filter(Profile.actor_id == actor.id):
            root = p.privilege == "elevated"
            p.account, p.expected_sid = ("root", "uid:0") if root else ("atomic-user", "uid:1001")
            p.logon_type = "systemd"
    response = env["client"].post(
        f"/api/v1/tests/{GUID}/review",
        headers={"X-Test-User": "admin"},
        json={
            "content_sha256": hash_value,
            "source_revision": revision,
            "allowed_profiles": ["standard-user", "local-admin"],
            "risk_level": "low",
        },
    )
    assert response.status_code == 200, response.text
    return env


def start(env, request_job, root=False):
    response = request_job(profile="local-admin" if root else "standard-user")
    assert response.status_code == 201, response.text
    run = response.json()
    approved = env["client"].post(
        f"/api/v1/runs/{run['run_id']}/approve",
        headers={"X-Test-User": "approver"},
        json={"reason": "Approved Linux simulated validation"},
    )
    assert approved.status_code == 200, approved.text
    job = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={}).json()["job"]
    assert job["snapshot"]["actor_os"] == "linux"
    return job


def evidence(job):
    s = job["snapshot"]
    uid = int(s["expected_sid"].split(":")[1])
    return {
        "platform": "linux",
        "expected_profile_id": s["execution_profile_id"],
        "expected_account_sid": s["expected_sid"],
        "actual_account_sid": s["expected_sid"],
        "actual_account_name": s["account"],
        "uid": uid,
        "euid": uid,
        "gid": uid,
        "egid": uid,
        "groups": [uid],
        "capabilities": "0" * 16,
        "permitted_capabilities": "0" * 16,
        "ambient_capabilities": "0" * 16,
        "bounding_capabilities": "0" * 16,
        "no_new_privileges": True,
        "elevated": uid == 0,
        "process_id": 1234,
        "verified": True,
    }


def submit(env, job, identity):
    return env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result",
        headers=env["agent"],
        json={
            "attempt_id": job["attempt_id"],
            "fence": job["fence"],
            "identity": identity,
            "status": "succeeded",
            "exit_code": 0,
            "stdout": "Synthetic Linux evidence; no real test executed",
            "started_at": time.time() - 1,
            "finished_at": time.time(),
            "simulated": False,
        },
    )


@pytest.mark.parametrize("root", [False, True])
def test_linux_approval_claim_and_kernel_identity_result(linux, request_job, root):
    job = start(linux, request_job, root)
    response = submit(linux, job, evidence(job))
    assert response.status_code == 200 and response.json()["status"] == "succeeded"
    run = linux["client"].get(f"/api/v1/runs/{job['run_id']}").json()
    assert run["result"]["identity_verified"] and run["result"]["identity"]["platform"] == "linux"


@pytest.mark.parametrize(
    "field,value",
    [
        ("euid", 0),
        ("groups", [0]),
        ("no_new_privileges", False),
        ("capabilities", "0000000000000001"),
        ("actual_account_name", "different-user"),
    ],
)
def test_linux_result_cannot_claim_success_with_wrong_identity(linux, request_job, field, value):
    job = start(linux, request_job)
    response = submit(linux, job, {**evidence(job), field: value})
    assert response.status_code == 200 and response.json()["status"] == "failed"


def test_linux_actor_rejects_windows_heartbeat_and_executor(linux, request_job):
    body = {
        "hostname": "WIN-TEST-01",
        "os_version": "forged Windows",
        "agent_version": "0.1.0",
        "revision": "demo",
        "profiles": {},
        "health": "healthy",
    }
    response = linux["client"].post("/api/v1/agents/heartbeat", headers=linux["agent"], json=body)
    assert response.status_code == 403
    with linux["app"].state.sessions() as db, db.begin():
        test = db.get(AtomicTest, GUID)
        test.definition = {
            **test.definition,
            "supported_platforms": ["windows", "linux"],
            "executor": {"name": "powershell", "command": "Write-Output synthetic"},
        }
        test.content_hash = fingerprint(test.definition)
        from apps.api.app.models import TestApproval

        review = db.get(TestApproval, GUID)
        review.content_hash = test.content_hash
    response = request_job()
    assert response.status_code == 409 and response.json()["error"]["code"] == "executor_unapproved"
