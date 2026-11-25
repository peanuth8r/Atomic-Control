from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from apps.api.app.models import Actor, AtomicTest, Lease, Profile, RunApproval
from apps.api.app.models import TestApproval as Approval
from tests.support.fixtures import fixture_result


def claim(env):
    return env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={})


def test_standard_and_admin_workflow_cleanup_audit(env, request_job):
    c = env["client"]
    identities = []
    for profile in ["standard-user", "local-admin"]:
        run = request_job(profile).json()
        assert run["status"] == "pending_approval"
        assert claim(env).json()["job"] is None
        c.post(
            f"/api/v1/runs/{run['run_id']}/approve",
            headers={"X-Test-User": "approver"},
            json={"reason": "Reviewed isolated host and exact operation"},
        ).raise_for_status()
        job = claim(env).json()["job"]
        renewal = c.post(
            f"/api/v1/agents/jobs/{run['run_id']}/heartbeat",
            headers=env["agent"],
            json={"attempt_id": job["attempt_id"], "fence": job["fence"]},
        )
        assert renewal.status_code == 200
        payload = fixture_result(job)
        endpoint = f"/api/v1/agents/jobs/{run['run_id']}/result"
        response = c.post(endpoint, headers=env["agent"], json=payload)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "succeeded"
        assert c.post(endpoint, headers=env["agent"], json=payload).status_code == 200
        detail = c.get(f"/api/v1/runs/{run['run_id']}").json()
        assert detail["result"]["identity_verified"]
        assert [e["status"] for e in detail["events"]] == [
            "pending_approval",
            "queued",
            "claimed",
            "running",
            "succeeded",
        ]
        identities.append(detail["result"]["identity"]["actual_account_sid"])
        cleanup = c.post(
            f"/api/v1/runs/{run['run_id']}/cleanup",
            headers={"X-Test-User": "operator", "Idempotency-Key": str(uuid4())},
            json={"reason": "Remove artifacts after completed validation"},
        )
        assert cleanup.status_code == 201, cleanup.text
        assert cleanup.json()["status"] == "pending_approval"
    assert identities[0] != identities[1]
    actions = [a["action"] for a in c.get("/api/v1/audit?limit=200").json()["items"]]
    assert "run.approve" in actions and "run.succeeded" in actions


def test_idempotency_and_conflict(env, request_job):
    first = request_job(key="same")
    assert first.status_code == 201
    assert request_job(key="same").json()["run_id"] == first.json()["run_id"]
    assert request_job(profile="local-admin", key="same").status_code == 409


def test_privileged_self_approval_forbidden(env, request_job):
    run = request_job(profile="local-admin", user="admin").json()
    response = env["client"].post(
        f"/api/v1/runs/{run['run_id']}/approve",
        headers={"X-Test-User": "admin"},
        json={"reason": "Approve privileged request for lab"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "self_approval"


def test_viewer_cannot_request_or_approve(env, request_job):
    assert request_job(user="viewer").status_code == 403
    run = request_job().json()
    assert (
        env["client"]
        .post(f"/api/v1/runs/{run['run_id']}/approve", json={"reason": "Attempt an unauthorized decision"})
        .status_code
        == 403
    )


@pytest.mark.parametrize(
    "change,code",
    [
        ("offline", "actor_offline"),
        ("unapproved", "test_unapproved"),
        ("profile", "profile_unavailable"),
        ("revision", "catalog_mismatch"),
    ],
)
def test_eligibility_fail_closed(env, request_job, change, code):
    with env["app"].state.sessions() as db, db.begin():
        if change == "offline":
            db.get(Actor, env["actor"]).last_heartbeat = 0
        elif change == "unapproved":
            db.get(Approval, "11111111-1111-4111-8111-111111111111").approved = False
        elif change == "profile":
            db.get(Profile, env["profiles"][0]["id"]).healthy = False
        elif change == "revision":
            db.get(Actor, env["actor"]).revision = "changed"
    response = request_job()
    assert response.json()["error"]["code"] == code


def test_expired_approval_not_claimed(env, approved_job):
    with env["app"].state.sessions() as db, db.begin():
        db.get(RunApproval, approved_job["run_id"]).expires_at = 0
    assert claim(env).json()["job"] is None
    assert env["client"].get(f"/api/v1/runs/{approved_job['run_id']}").json()["status"] == "rejected"


def test_concurrent_claim_only_once(env, approved_job):
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: claim(env), range(4)))
    assert sum(r.json()["job"] is not None for r in responses) == 1


def test_stale_fence_cannot_report(env, approved_job):
    job = claim(env).json()["job"]
    payload = fixture_result(job)
    payload["fence"] = "f" * 64
    response = env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=env["agent"], json=payload
    )
    assert response.json()["error"]["code"] == "stale_lease"


def test_lease_expiry_inconclusive_and_no_retry(env, approved_job, request_job):
    job = claim(env).json()["job"]
    with env["app"].state.sessions() as db, db.begin():
        db.get(Lease, env["actor"]).expires_at = 0
    assert claim(env).json()["job"] is None
    response = env["client"].get(f"/api/v1/runs/{job['run_id']}").json()
    assert response["status"] == "inconclusive"
    assert (
        env["client"]
        .post(f"/api/v1/agents/jobs/{job['run_id']}/result", headers=env["agent"], json=fixture_result(job))
        .status_code
        == 409
    )
    reconciled = env["client"].post(
        f"/api/v1/runs/{job['run_id']}/reconcile",
        headers={"X-Test-User": "admin"},
        json={"reason": "Verified process tree stopped and artifacts inspected"},
    )
    assert reconciled.status_code == 200


def test_identity_mismatch_cannot_succeed(env, approved_job):
    job = claim(env).json()["job"]
    payload = fixture_result(job)
    payload["identity"]["elevated"] = True
    response = env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=env["agent"], json=payload
    )
    assert response.json()["status"] == "failed"


def test_arbitrary_command_fields_rejected(env, request_job):
    run = request_job().json()
    body = {
        "atomic_guid": run["snapshot"]["atomic_guid"],
        "actor_id": env["actor"],
        "execution_profile_id": run["execution_profile_id"],
        "reason": "Test schema rejects command injection",
        "command": "whoami",
    }
    response = env["client"].post(
        "/api/v1/runs", json=body, headers={"X-Test-User": "operator", "Idempotency-Key": "inject"}
    )
    assert response.status_code == 422
    assert "whoami" not in response.text


def test_cancellation_signal(env, approved_job):
    job = claim(env).json()["job"]
    c = env["client"]
    c.post(
        f"/api/v1/runs/{job['run_id']}/cancel",
        headers={"X-Test-User": "operator"},
        json={"reason": "Stop authorized validation request"},
    ).raise_for_status()
    assert c.post(
        f"/api/v1/agents/jobs/{job['run_id']}/heartbeat",
        headers=env["agent"],
        json={"attempt_id": job["attempt_id"], "fence": job["fence"]},
    ).json()["cancel_requested"]


def test_changed_catalog_blocks_claim(env, approved_job):
    with env["app"].state.sessions() as db, db.begin():
        db.get(AtomicTest, "11111111-1111-4111-8111-111111111111").content_hash = "0" * 64
    assert claim(env).json()["error"]["code"] == "test_unapproved"


def test_logs_redact_and_results_immutable(env, approved_job):
    job = claim(env).json()["job"]
    payload = fixture_result(job)
    payload["stdout"] = "password=do-not-store access_token=hidden"
    path = f"/api/v1/agents/jobs/{job['run_id']}/result"
    env["client"].post(path, headers=env["agent"], json=payload).raise_for_status()
    logs = env["client"].get(f"/api/v1/runs/{job['run_id']}/logs").text
    assert "do-not-store" not in logs and "hidden" not in logs
    payload["stdout"] = "different"
    assert env["client"].post(path, headers=env["agent"], json=payload).status_code == 409


def test_unknown_actor_profile_and_guid(env, request_job):
    run = request_job().json()
    body = {
        "atomic_guid": run["snapshot"]["atomic_guid"],
        "actor_id": env["actor"],
        "execution_profile_id": run["execution_profile_id"],
        "reason": "Unknown resources must be rejected",
    }
    for field in ["atomic_guid", "actor_id", "execution_profile_id"]:
        invalid = {**body, field: str(uuid4())}
        assert (
            env["client"]
            .post(
                "/api/v1/runs",
                json=invalid,
                headers={"X-Test-User": "operator", "Idempotency-Key": str(uuid4())},
            )
            .status_code
            == 409
        )


def test_agent_authentication_and_identity_headers_are_denied(env):
    assert env["client"].post("/api/v1/agents/jobs/claim").status_code == 401
    from fastapi.testclient import TestClient

    from apps.api.app.auth import human

    env["app"].dependency_overrides.pop(human)
    remote = TestClient(env["app"], client=("192.0.2.1", 1234))
    assert remote.get("/api/v1/actors", headers={"X-Dev-User": "admin"}).status_code == 401
    assert env["client"].get("/api/v1/actors", headers={"X-Test-User": "admin"}).status_code == 401


def test_cleanup_approved_and_completed_independently(env, approved_job):
    c = env["client"]
    job = claim(env).json()["job"]
    c.post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=env["agent"], json=fixture_result(job)
    ).raise_for_status()
    cleanup = c.post(
        f"/api/v1/runs/{job['run_id']}/cleanup",
        headers={"X-Test-User": "operator", "Idempotency-Key": "cleanup-e2e"},
        json={"reason": "Restore lab state after authorized validation"},
    ).json()
    assert cleanup["status"] == "pending_approval"
    assert claim(env).json()["job"] is None
    c.post(
        f"/api/v1/runs/{cleanup['run_id']}/approve",
        headers={"X-Test-User": "approver"},
        json={"reason": "Reviewed cleanup in original execution context"},
    ).raise_for_status()
    clean_job = claim(env).json()["job"]
    assert clean_job["snapshot"]["action"] == "cleanup"
    c.post(
        f"/api/v1/agents/jobs/{clean_job['run_id']}/result",
        headers=env["agent"],
        json=fixture_result(clean_job),
    ).raise_for_status()
    assert c.get(f"/api/v1/runs/{job['run_id']}").json()["cleanup_status"] == "succeeded"
    assert c.get(f"/api/v1/runs/{job['run_id']}").json()["status"] == "succeeded"
