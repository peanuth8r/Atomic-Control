"""Queue protocol tests use isolated records and synthetic results; no Atomic commands run."""

import copy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from apps.api.app.main import create_app
from apps.api.app.models import Actor, AtomicTest, Lease, Profile, Run, RunApproval, RunBatch
from apps.api.app.models import TestApproval as Review
from apps.api.app.services.common import fingerprint
from tests.support.fixtures import fixture_result

GUID = "11111111-1111-4111-8111-111111111111"
OP = {"X-Test-User": "operator"}
REASON = {"reason": "Authorized queue protocol validation"}


@pytest.fixture
def queue_env(env):
    env["settings"].approval_mode = "catalog"
    guids = [GUID]
    with env["app"].state.sessions() as db, db.begin():
        original = db.get(AtomicTest, GUID)
        for index in range(2):
            guid = str(uuid4())
            definition = copy.deepcopy(original.definition)
            definition.update(auto_generated_guid=guid, name=f"Ordered fixture {index + 2}")
            row = AtomicTest(
                guid=guid,
                technique=original.technique,
                name=definition["name"],
                revision=original.revision,
                content_hash=fingerprint(definition),
                definition=definition,
                simulated=False,
            )
            db.add(row)
            db.flush()
            db.add(
                Review(
                    guid=guid,
                    revision=row.revision,
                    content_hash=row.content_hash,
                    allowed_profiles=["standard-user"],
                    allowed_platforms=["windows"],
                    risk_level="low",
                    approved_by="fixture:reviewer",
                    approved=True,
                )
            )
            guids.append(guid)
    # Per-run scope is deliberately explicit; never use a live policy file.
    policy = yaml.safe_load(open(env["settings"].policy_file))
    for grants in policy["subjects"].values():
        grants[0]["tests"] = guids
    with open(env["settings"].policy_file, "w") as output:
        yaml.safe_dump(policy, output)
    env["guids"] = guids
    env["profile"] = next(p["id"] for p in env["profiles"] if p["profile_key"] == "standard-user")
    return env


def preview(env, guids=None, **extra):
    body = {"execution_profile_id": env["profile"], "atomic_guids": guids or env["guids"], **extra}
    response = env["client"].post(f"/api/v1/actors/{env['actor']}/queue/preview", headers=OP, json=body)
    assert response.status_code == 200, response.text
    return response.json(), body


def submit(env, key=None, guids=None, **extra):
    selection, body = preview(env, guids)
    body.update(preview_hash=selection["preview_hash"], name="Protocol fixtures", **REASON, **extra)
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/queue",
        headers={**OP, "Idempotency-Key": key or str(uuid4())},
        json=body,
    )
    assert response.status_code == 201, response.text
    return response.json(), body


def detail(env, batch):
    response = env["client"].get(f"/api/v1/run-batches/{batch['id']}")
    assert response.status_code == 200, response.text
    return response.json()


def control(env, batch, action):
    return env["client"].post(f"/api/v1/run-batches/{batch['id']}/{action}", headers=OP, json={})


def claim(env):
    response = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={})
    assert response.status_code == 200, response.text
    return response.json()["job"]


def finish(env, job, **extra):
    response = env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result",
        headers=env["agent"],
        json={**fixture_result(job), **extra},
    )
    assert response.status_code == 200, response.text


def approve(env, run_id):
    response = env["client"].post(
        f"/api/v1/runs/{run_id}/approve", headers={"X-Test-User": "approver"}, json=REASON
    )
    assert response.status_code == 200, response.text


def test_preview_exclusions_deduplication_and_stale_binding(queue_env):
    env = queue_env
    missing = str(uuid4())
    selection, body = preview(env, [GUID, GUID, missing])
    assert selection["selected_count"] == 2
    assert selection["eligible_count"] == 1
    assert selection["items"][1]["error"] == "test_unapproved"
    with env["app"].state.sessions() as db, db.begin():
        db.get(Review, GUID).approved = False
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/queue",
        headers={**OP, "Idempotency-Key": "stale"},
        json={**body, **REASON, "preview_hash": selection["preview_hash"]},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "queue_preview_changed"
    with env["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(RunBatch)) == 0
        assert db.scalar(select(func.count()).select_from(Run)) == 0


def test_only_eligible_items_submitted_and_filterable(queue_env):
    batch, _ = submit(queue_env, guids=[GUID, str(uuid4())])
    assert batch["total"] == 1
    assert batch["failure_policy"] == "continue"
    rows = queue_env["client"].get(f"/api/v1/runs?batch_id={batch['id']}").json()
    assert rows["total"] == 1
    assert rows["items"][0]["batch_id"] == batch["id"]
    assert rows["items"][0]["queue_position"] == 1


def test_idempotent_retry_and_conflict(queue_env):
    env = queue_env
    batch, body = submit(env, key="stable-batch")
    url = f"/api/v1/actors/{env['actor']}/queue"
    headers = {**OP, "Idempotency-Key": "stable-batch"}
    assert env["client"].post(url, headers=headers, json=body).json()["id"] == batch["id"]
    assert env["client"].post(url, headers=headers, json={**body, "name": "changed"}).status_code == 409
    assert env["client"].get("/api/v1/runs").json()["total"] == 3


def test_concurrent_retry_creates_one_batch(queue_env):
    env = queue_env
    selection, body = preview(env)
    body.update(preview_hash=selection["preview_hash"], **REASON)
    barrier = Barrier(2)

    def send():
        barrier.wait()
        return env["client"].post(
            f"/api/v1/actors/{env['actor']}/queue",
            headers={**OP, "Idempotency-Key": "concurrent-batch"},
            json=body,
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        replies = list(workers.map(lambda _: send(), range(2)))
    assert [r.status_code for r in replies] == [201, 201]
    assert replies[0].json()["id"] == replies[1].json()["id"]
    assert env["client"].get("/api/v1/runs").json()["total"] == 3


def test_fifo_batches_and_single_requests_share_one_actor_lease(queue_env, request_job):
    env = queue_env
    first = request_job().json()
    batch, _ = submit(env, guids=list(reversed(env["guids"])))
    last = request_job().json()
    expected = [first["run_id"], *[r["run_id"] for r in batch["items"]], last["run_id"]]
    for run_id in expected:
        job = claim(env)
        assert job["run_id"] == run_id
        assert claim(env) is None
        finish(env, job)
    assert claim(env) is None
    assert detail(env, batch)["status"] == "completed"


def test_pause_finishes_active_then_holds_later_work_and_cancel_releases(queue_env, request_job):
    env = queue_env
    batch, _ = submit(env)
    later = request_job().json()
    job = claim(env)
    assert control(env, batch, "pause").json()["status"] == "pausing"
    finish(env, job)
    assert claim(env) is None
    assert control(env, batch, "cancel").json()["status"] == "cancelled"
    assert claim(env)["run_id"] == later["run_id"]
    assert detail(env, batch)["counts"] == {"succeeded": 1, "cancelled": 2}


def test_cancel_remaining_does_not_cancel_active(queue_env):
    env = queue_env
    batch, _ = submit(env)
    job = claim(env)
    assert control(env, batch, "cancel").json()["status"] == "cancelling"
    with env["app"].state.sessions() as db:
        assert not db.get(Run, job["run_id"]).cancel_requested
    finish(env, job)
    assert claim(env) is None
    assert detail(env, batch)["status"] == "cancelled"


@pytest.mark.parametrize("policy,paused", [("pause", True), ("continue", False)])
def test_failure_policy_and_resume(queue_env, policy, paused):
    env = queue_env
    batch, _ = submit(env, failure_policy=policy)
    finish(env, claim(env), status="failed", exit_code=1)
    assert detail(env, batch)["paused"] is paused
    if paused:
        assert claim(env) is None
        assert control(env, batch, "resume").status_code == 200
    job = claim(env)
    assert job["run_id"] == batch["items"][1]["run_id"]
    finish(env, job)
    finish(env, claim(env))
    assert detail(env, batch)["status"] == "completed_with_errors"


def test_identity_failure_always_pauses_continue_policy(queue_env):
    env = queue_env
    batch, _ = submit(env, failure_policy="continue")
    job = claim(env)
    identity = fixture_result(job)["identity"]
    identity["actual_account_sid"] = "S-1-5-21-incorrect"
    finish(env, job, identity=identity)
    assert detail(env, batch)["pause_reason"] == "identity_verification_failed"
    assert claim(env) is None


def test_inconclusive_requires_reconciliation_even_when_batch_cancelled(queue_env, request_job):
    env = queue_env
    batch, _ = submit(env, failure_policy="continue")
    job = claim(env)
    finish(env, job, status="inconclusive")
    assert control(env, batch, "resume").json()["error"]["code"] == "queue_reconciliation_required"
    assert control(env, batch, "cancel").status_code == 200
    later = request_job().json()
    assert claim(env) is None
    assert (
        env["client"]
        .post(f"/api/v1/runs/{job['run_id']}/reconcile", headers={"X-Test-User": "admin"}, json=REASON)
        .status_code
        == 200
    )
    assert claim(env)["run_id"] == later["run_id"]


def test_lease_expiry_pauses_without_retry(queue_env):
    env = queue_env
    batch, _ = submit(env)
    job = claim(env)
    with env["app"].state.sessions() as db, db.begin():
        db.get(Lease, env["actor"]).expires_at = 0
    assert claim(env) is None
    assert detail(env, batch)["paused"]
    assert env["client"].get(f"/api/v1/runs/{job['run_id']}").json()["status"] == "inconclusive"


@pytest.mark.parametrize("change", ["revoke", "definition", "profile", "mode"])
def test_dispatch_revalidates_catalog_definition_identity_and_mode(queue_env, change):
    env = queue_env
    batch, _ = submit(env)
    with env["app"].state.sessions() as db, db.begin():
        if change == "revoke":
            db.get(Review, GUID).approved = False
        elif change == "definition":
            row = db.get(AtomicTest, GUID)
            row.definition = {**row.definition, "description": "Changed after preview"}
            row.content_hash = fingerprint(row.definition)
        elif change == "profile":
            db.get(Profile, env["profile"]).account = "different-account"
    if change == "mode":
        env["settings"].approval_mode = "per_run"
    assert claim(env) is None
    current = detail(env, batch)
    assert current["paused"]
    assert current["items"][0]["status"] == ("queued" if change == "mode" else "rejected")


def test_catalog_authorization_renews_only_after_current_review_checks(queue_env):
    env = queue_env
    batch, _ = submit(env)
    with env["app"].state.sessions() as db, db.begin():
        for item in batch["items"]:
            db.get(RunApproval, item["run_id"]).expires_at = 0
    job = claim(env)
    assert job["run_id"] == batch["items"][0]["run_id"]
    finish(env, job)
    with env["app"].state.sessions() as db, db.begin():
        db.get(Review, env["guids"][1]).approved = False
    assert claim(env) is None
    with env["app"].state.sessions() as db:
        assert db.get(RunApproval, batch["items"][1]["run_id"]).expires_at == 0


def test_per_run_approval_expiry_requires_fresh_human_approval_and_resume(queue_env):
    env = queue_env
    env["settings"].approval_mode = "per_run"
    batch, _ = submit(env)
    run_id = batch["items"][0]["run_id"]
    # Approving later rows cannot bypass the actor's pending head.
    approve(env, batch["items"][1]["run_id"])
    assert claim(env) is None
    approve(env, run_id)
    with env["app"].state.sessions() as db, db.begin():
        db.get(RunApproval, run_id).expires_at = 0
    assert claim(env) is None
    assert detail(env, batch)["pause_reason"] == "approval_expired"
    assert control(env, batch, "resume").status_code == 409
    approve(env, run_id)
    # Only the expired head needs renewal, later pending requests may remain pending.
    assert control(env, batch, "resume").status_code == 200
    assert claim(env)["run_id"] == run_id


def test_requester_scope_revocation_blocks_per_run_dispatch(queue_env):
    env = queue_env
    env["settings"].approval_mode = "per_run"
    batch, _ = submit(env)
    approve(env, batch["items"][0]["run_id"])
    with open(env["settings"].policy_file, "w") as output:
        yaml.safe_dump({"subjects": {}}, output)
    assert claim(env) is None
    assert detail(env, batch)["paused"]


def test_expired_queue_never_dispatches_and_active_test_can_finish(queue_env):
    env = queue_env
    batch, _ = submit(env)
    job = claim(env)
    with env["app"].state.sessions() as db, db.begin():
        db.get(RunBatch, batch["id"]).expires_at = 0
    finish(env, job)
    assert claim(env) is None
    current = detail(env, batch)
    assert current["status"] == "expired"
    assert current["counts"] == {"succeeded": 1, "cancelled": 2}
    assert control(env, batch, "resume").status_code == 409


def test_actor_deletion_cancels_batches_preserves_history_and_releases_hostname(queue_env):
    env = queue_env
    batch, _ = submit(env)
    reply = env["client"].post(
        f"/api/v1/actors/{env['actor']}/retire",
        headers={"X-Test-User": "admin"},
        json={"hostname": "WIN-TEST-01"},
    )
    assert reply.status_code == 200, reply.text
    assert detail(env, batch)["status"] == "cancelled"
    with env["app"].state.sessions() as db, db.begin():
        actor = Actor(hostname="WIN-TEST-01")
        db.add(actor)
        db.flush()
        new_id = actor.id
    assert env["client"].get(f"/api/v1/actors/{new_id}/queue").json()["total"] == 0
    assert env["client"].get(f"/api/v1/actors/{env['actor']}/queue").json()["total"] == 1
    assert all(item["status"] == "cancelled" for item in detail(env, batch)["items"])


def test_restart_preserves_batch_order_and_pause(queue_env):
    env = queue_env
    batch, _ = submit(env)
    control(env, batch, "pause")
    app = create_app(env["settings"])
    app.dependency_overrides = dict(env["app"].dependency_overrides)
    env["client"] = TestClient(app)
    assert detail(env, batch)["items"] == batch["items"]
    assert claim(env) is None
    assert control(env, batch, "resume").status_code == 200
    assert claim(env)["run_id"] == batch["items"][0]["run_id"]
    app.state.engine.dispose()


@pytest.mark.parametrize("user", ["viewer", "approver"])
def test_read_only_roles_cannot_submit_or_control(queue_env, user):
    env = queue_env
    batch, body = submit(env)
    headers = {"X-Test-User": user, "Idempotency-Key": str(uuid4())}
    assert (
        env["client"].post(f"/api/v1/actors/{env['actor']}/queue", headers=headers, json=body).status_code
        == 403
    )
    assert env["client"].post(f"/api/v1/run-batches/{batch['id']}/cancel", headers=headers).status_code == 403
    assert env["client"].get(f"/api/v1/actors/{env['actor']}/queue", headers=headers).status_code == 200


def test_selection_limit_and_empty_eligibility(queue_env):
    env = queue_env
    body = {"execution_profile_id": env["profile"], "atomic_guids": [str(uuid4()) for _ in range(501)]}
    assert (
        env["client"].post(f"/api/v1/actors/{env['actor']}/queue/preview", headers=OP, json=body).status_code
        == 422
    )
    selection, body = preview(env, [str(uuid4())])
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/queue",
        headers={**OP, "Idempotency-Key": "empty"},
        json={**body, **REASON, "preview_hash": selection["preview_hash"]},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "queue_empty"


def test_later_paused_batch_does_not_block_earlier_batch(queue_env):
    env = queue_env
    first, _ = submit(env)
    second, _ = submit(env)
    control(env, second, "pause")
    for item in first["items"]:
        job = claim(env)
        assert job["run_id"] == item["run_id"]
        finish(env, job)
    assert claim(env) is None
    assert control(env, second, "resume").status_code == 200
    assert claim(env)["run_id"] == second["items"][0]["run_id"]


def test_cancellation_with_unverified_identity_also_holds_continue_batch(queue_env):
    env = queue_env
    batch, _ = submit(env, failure_policy="continue")
    job = claim(env)
    identity = fixture_result(job)["identity"]
    identity["verified"] = False
    finish(env, job, status="cancelled", identity=identity)
    assert detail(env, batch)["pause_reason"] == "identity_verification_failed"
    assert claim(env) is None


def test_terminal_batch_controls_do_not_rewrite_completion(queue_env):
    env = queue_env
    batch, _ = submit(env, guids=[GUID])
    finish(env, claim(env))
    assert control(env, batch, "pause").status_code == 409
    assert control(env, batch, "resume").status_code == 409
    assert control(env, batch, "cancel").json()["status"] == "completed"


def test_submission_retry_after_actor_deletion_returns_original_receipt(queue_env):
    env = queue_env
    batch, body = submit(env, key="deleted-retry")
    env["client"].post(
        f"/api/v1/actors/{env['actor']}/retire",
        headers={"X-Test-User": "admin"},
        json={"hostname": "WIN-TEST-01"},
    ).raise_for_status()
    reply = env["client"].post(
        f"/api/v1/actors/{env['actor']}/queue", headers={**OP, "Idempotency-Key": "deleted-retry"}, json=body
    )
    assert reply.status_code == 201
    assert reply.json()["id"] == batch["id"]
    assert reply.json()["status"] == "cancelled"
