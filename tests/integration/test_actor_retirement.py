import io
import json
import secrets
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.app.auth import Principal, human
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import (
    Actor,
    Audit,
    Base,
    Cleanup,
    Credential,
    Enrollment,
    Lease,
    Log,
    Profile,
    ProfileSync,
    Run,
)
from apps.api.app.models import (
    TestApproval as CatalogApproval,
)
from apps.api.app.services.common import digest

ADMIN = {"X-Test-User": "admin"}
REASON = "Host decommissioned after authorized lab validation"


def retire(env, **overrides):
    return env["client"].post(
        f"/api/v1/actors/{env['actor']}/retire",
        headers=ADMIN,
        json={"hostname": "WIN-TEST-01", "reason": REASON, **overrides},
    )


def test_retirement_revokes_access_cancels_pending_work_and_keeps_history(env, request_job, approved_job):
    pending = request_job(profile="local-admin").json()
    historical = request_job(key="historical-evidence").json()
    token = secrets.token_urlsafe(48)
    other_actor = str(uuid4())
    with env["app"].state.sessions() as db, db.begin():
        db.add(Actor(id=other_actor, hostname="other-host"))
        db.flush()
        db.add(Credential(actor_id=env["actor"], digest=digest(token), expires_at=time.time() + 1000))
        db.add(Credential(actor_id=other_actor, digest=digest("other"), expires_at=time.time() + 1000))
        db.add_all(
            [
                Enrollment(
                    actor_id=env["actor"],
                    hostname="WIN-TEST-01",
                    digest=digest("bound"),
                    expires_at=time.time() + 600,
                ),
                Enrollment(hostname="win-test-01", digest=digest("legacy"), expires_at=time.time() + 600),
                Enrollment(
                    actor_id=other_actor,
                    hostname="other-host",
                    digest=digest("unrelated"),
                    expires_at=time.time() + 600,
                ),
            ]
        )
        run = db.get(Run, historical["run_id"])
        run.status, run.result = "succeeded", {"stdout": "preserved synthetic evidence"}
        db.add(Log(run_id=run.id, content="preserved log"))
        db.add(
            ProfileSync(
                actor_id=env["actor"],
                generation=1,
                payload={"profiles": []},
                payload_hash="a" * 64,
                requested_by="admin",
                status="pending",
            )
        )
        review = db.scalar(select(CatalogApproval))
        original_review = review.content_hash, review.revision, review.approved
    cleanup = env["client"].post(
        f"/api/v1/runs/{historical['run_id']}/cleanup",
        headers={"X-Test-User": "operator", "Idempotency-Key": "pending-cleanup-fixture"},
        json={"reason": "Synthetic cleanup waiting for approval"},
    )
    assert cleanup.status_code == 201, cleanup.text
    cleanup_id = cleanup.json()["run_id"]
    response = retire(env, reason="  " + REASON + "  ")
    assert response.status_code == 200, response.text
    actor = response.json()
    assert actor["deleted"] is True and actor["id"] == env["actor"]
    assert actor["hostname"] == "WIN-TEST-01"
    assert actor["deleted_by"] == "dev:admin" and actor["reason"] == REASON and actor["deleted_at"] > 0
    assert env["client"].get("/api/v1/actors").json()["total"] == 1
    assert env["client"].get("/api/v1/actors?include_retired=true").json()["total"] == 1
    assert env["client"].get(f"/api/v1/actors/{env['actor']}").status_code == 404
    evidence = env["client"].get(f"/api/v1/runs/{historical['run_id']}")
    assert evidence.status_code == 200 and evidence.json()["snapshot"]["hostname"] == "WIN-TEST-01"
    assert env["client"].get(f"/api/v1/runs/{historical['run_id']}/logs").json()["content"] == "preserved log"
    with env["app"].state.sessions() as db:
        assert db.get(Actor, env["actor"]) is None
        assert db.scalar(select(Profile).where(Profile.actor_id == env["actor"])) is None
        assert db.scalar(select(Credential).where(Credential.actor_id == env["actor"])) is None
        assert not db.scalar(select(Credential).where(Credential.actor_id == other_actor)).revoked
        assert (
            db.scalar(select(Enrollment).where(Enrollment.digest.in_([digest("bound"), digest("legacy")])))
            is None
        )
        assert not db.scalar(select(Enrollment).where(Enrollment.digest == digest("unrelated"))).used
        for run_id in (pending["run_id"], approved_job["run_id"], cleanup_id):
            assert db.get(Run, run_id).status == "cancelled" and db.get(Run, run_id).cancel_requested
        assert db.get(Cleanup, cleanup_id).status == "cancelled"
        assert db.get(Run, historical["run_id"]).result == {"stdout": "preserved synthetic evidence"}
        assert db.get(Log, historical["run_id"]).content == "preserved log"
        assert db.scalar(select(ProfileSync)) is None
        audit = db.scalar(select(Audit).where(Audit.action == "actor.deleted"))
        assert (
            audit.details["credentials_revoked"] == 2 and audit.details["enrollment_tokens_invalidated"] == 2
        )
        assert audit.details["runs_cancelled"] == 3 and audit.details["reason"] == REASON
        review = db.scalar(select(CatalogApproval))
        assert (review.content_hash, review.revision, review.approved) == original_review


def test_deletion_is_idempotent_and_hostname_can_be_registered_again(env, request_job):
    original = retire(env).json()
    assert original["deleted"] is True
    assert retire(env, reason="A repeated request after a lost acknowledgment").json() == original
    for path in ("enable", "disable", "profile-sync"):
        assert (
            env["client"].post(f"/api/v1/actors/{env['actor']}/{path}", headers=ADMIN, json={}).status_code
            == 404
        )
    assert request_job().status_code == 409
    replacement = env["client"].post("/api/v1/actors", headers=ADMIN, json={"hostname": "win-test-01"})
    assert replacement.status_code == 201, replacement.text
    new = replacement.json()
    assert new["id"] != env["actor"] and new["registration_state"] == "pending_enrollment"
    assert not new["profiles"]
    assert (
        env["client"]
        .post("/api/v1/enrollment-tokens", headers=ADMIN, json={"hostname": "win-test-01"})
        .status_code
        == 200
    )
    assert (
        env["client"]
        .post(
            f"/api/v1/actors/{env['actor']}/agent-package",
            headers=ADMIN,
            json={"api_url": "https://control.example.test", "include_enrollment": False},
        )
        .status_code
        == 404
    )
    assert (
        env["client"]
        .post(
            f"/api/v1/actors/{env['actor']}/profiles",
            headers=ADMIN,
            json={
                "profile_key": "standard-user",
                "display_name": "Replacement",
                "account": "user",
                "expected_sid": "S-1-5-21-123-1001",
                "privilege": "standard",
            },
        )
        .status_code
        == 404
    )
    for path in ("heartbeat", "jobs/claim", "credentials/rotate", "profile-sync/poll"):
        response = env["client"].post("/api/v1/agents/" + path, headers=env["agent"], json={})
        assert response.status_code == 401, response.text
    # A retry of the original deletion must never delete the replacement identity.
    assert retire(env).json() == original
    assert env["client"].get(f"/api/v1/actors/{new['id']}").status_code == 200
    with env["app"].state.sessions() as db:
        assert len(db.scalars(select(Audit).where(Audit.action == "actor.deleted")).all()) == 1


def test_previously_archived_actor_can_be_permanently_deleted(env):
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.registration_state, actor.enabled, actor.health = "retired", False, "retired"
    assert retire(env).json()["deleted"] is True
    assert (
        env["client"].post("/api/v1/actors", headers=ADMIN, json={"hostname": "WIN-TEST-01"}).status_code
        == 201
    )


@pytest.mark.parametrize(
    "body",
    [{}, {"reason": None}, {"reason": ""}, {"reason": "   "}, {"reason": "x"}, {"reason": "  short  "}],
)
@pytest.mark.parametrize("legacy", [False, True])
def test_retirement_reason_is_optional_for_current_and_archived_actors(env, body, legacy):
    if legacy:
        with env["app"].state.sessions() as db, db.begin():
            actor = db.get(Actor, env["actor"])
            actor.registration_state, actor.enabled = "retired", False
    expected = (body.get("reason") or "").strip()
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/retire",
        headers=ADMIN,
        json={"hostname": "WIN-TEST-01", **body},
    )
    assert response.status_code == 200, response.text
    assert response.json()["deleted"] is True and response.json()["reason"] == expected
    with env["app"].state.sessions() as db:
        assert db.get(Actor, env["actor"]) is None
        assert db.scalar(select(Audit).where(Audit.action == "actor.deleted")).details["reason"] == expected
    assert (
        retire(env, reason="A later retry must retain the original optional reason").json() == response.json()
    )


@pytest.mark.parametrize(
    "body", [{"hostname": "wrong-host"}, {"reason": "x" * 2001}, {"reason": 42}, {"unexpected": True}]
)
def test_retirement_requires_exact_confirmation_and_bounded_optional_reason(env, body):
    assert retire(env, **body).status_code == 422
    with env["app"].state.sessions() as db:
        assert db.get(Actor, env["actor"]).enabled
        assert not db.scalar(select(Credential)).revoked


@pytest.mark.parametrize("user", ["viewer", "operator", "approver"])
def test_only_human_administrators_can_retire(env, user):
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/retire",
        headers={"X-Test-User": user},
        json={"hostname": "WIN-TEST-01", "reason": REASON},
    )
    assert response.status_code == 403


def test_mcp_identity_cannot_retire_even_with_administrator_claim(env):
    env["app"].dependency_overrides[human] = lambda: Principal(
        "mcp", frozenset({"administrator"}), frozenset(), True
    )
    assert retire(env).status_code == 403


@pytest.mark.parametrize("state", ["claimed", "running", "inconclusive", "expired_lease"])
def test_unresolved_execution_blocks_retirement_atomically(env, approved_job, state):
    client = env["client"]
    if state == "expired_lease":
        assert client.post("/api/v1/agents/jobs/claim", headers=env["agent"]).json()["job"]
    with env["app"].state.sessions() as db, db.begin():
        if state == "expired_lease":
            db.get(Lease, env["actor"]).expires_at = 0
        else:
            db.get(Run, approved_job["run_id"]).status = state
    response = retire(env)
    assert response.status_code == 409 and response.json()["error"]["code"] == "actor_busy"
    with env["app"].state.sessions() as db:
        assert db.get(Actor, env["actor"]).registration_state == "enrolled"
        assert not db.scalar(select(Credential)).revoked
        assert db.scalar(select(Audit).where(Audit.action == "actor.deleted")) is None


def test_reconciled_inconclusive_evidence_survives_retirement(env, approved_job):
    env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"])
    with env["app"].state.sessions() as db, db.begin():
        db.get(Lease, env["actor"]).expires_at = 0
    run = env["client"].get(f"/api/v1/runs/{approved_job['run_id']}").json()
    assert run["status"] == "inconclusive"
    assert retire(env).status_code == 409
    response = env["client"].post(
        f"/api/v1/runs/{approved_job['run_id']}/reconcile",
        headers=ADMIN,
        json={"reason": "Operator verified that the synthetic job has stopped"},
    )
    assert response.status_code == 200
    assert retire(env).status_code == 200
    with env["app"].state.sessions() as db:
        assert db.get(Run, approved_job["run_id"]).status == "inconclusive"
        assert db.get(Run, approved_job["run_id"]).reconciled


@pytest.fixture
def real_actor(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = tmp_path / "signer.pem"
    signer.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    settings = Settings(
        mode="real",
        database_url=f"sqlite:///{tmp_path}/real.db",
        signing_key_file=str(signer),
        public_url="https://control.example.test",
        oidc_issuer="https://id.example.test",
        oidc_jwks_url="https://id.example.test/jwks",
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    app.dependency_overrides[human] = lambda: Principal(
        "human-admin", frozenset({"administrator", "viewer"}), frozenset()
    )
    client = TestClient(app)
    actor = client.post("/api/v1/actors", json={"hostname": "linux-retirement-fixture", "os": "linux"}).json()
    package = client.post(
        f"/api/v1/actors/{actor['id']}/agent-package",
        json={"api_url": settings.public_url, "include_enrollment": True},
    )
    assert package.status_code == 200, package.text
    with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
        bootstrap = json.loads(archive.read("AtomicControlAgent/bootstrap.json"))
    enrollment = {
        "token": bootstrap["enrollment_token"],
        "hostname": actor["hostname"],
        "os": "linux",
        "os_version": "Linux",
        "agent_version": "0.1.0",
    }
    response = client.post("/api/v1/agents/enroll", json=enrollment)
    assert response.status_code == 200, response.text
    return {
        "app": app,
        "client": client,
        "actor": actor,
        "enrollment": enrollment,
        "credential": response.json()["credential"],
    }


@pytest.mark.parametrize("bound", [False, True])
def test_retired_actor_cannot_be_reenrolled_through_either_token_path(real_actor, bound):
    s = real_actor
    actor = s["actor"]
    # A currently unused legacy or actor-bound token is invalidated at retirement.
    token = secrets.token_urlsafe(48)
    with s["app"].state.sessions() as db, db.begin():
        db.add(
            Enrollment(
                actor_id=actor["id"] if bound else None,
                hostname=actor["hostname"],
                os="linux",
                digest=digest(token),
                expires_at=time.time() + 600,
            )
        )
    response = s["client"].post(
        f"/api/v1/actors/{actor['id']}/retire", json={"hostname": actor["hostname"], "reason": REASON}
    )
    assert response.status_code == 200
    body = {**s["enrollment"], "token": token}
    assert s["client"].post("/api/v1/agents/enroll", json=body).status_code == 401
    replacement = s["client"].post("/api/v1/actors", json={"hostname": actor["hostname"], "os": "linux"})
    assert replacement.status_code == 201
    new = replacement.json()
    assert new["id"] != actor["id"]
    assert s["client"].post("/api/v1/agents/enroll", json=body).status_code == 401
    package = s["client"].post(
        f"/api/v1/actors/{new['id']}/agent-package",
        json={"api_url": "https://control.example.test", "include_enrollment": True},
    )
    assert package.status_code == 200
    with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
        fresh = json.loads(archive.read("AtomicControlAgent/bootstrap.json"))
    enrolled = s["client"].post("/api/v1/agents/enroll", json={**body, "token": fresh["enrollment_token"]})
    assert enrolled.status_code == 200 and enrolled.json()["actor_id"] == new["id"]
    assert (
        s["client"]
        .post(
            "/api/v1/agents/credentials/rotate",
            headers={"Authorization": "Bearer " + s["credential"]},
        )
        .status_code
        == 401
    )


@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_retirement_and_claim_cannot_both_succeed(env, approved_job, attempt):
    barrier = Barrier(2)

    def claim():
        barrier.wait()
        return env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"])

    def retirement():
        barrier.wait()
        return retire(env)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claim_future, retire_future = pool.submit(claim), pool.submit(retirement)
        claim_response, retire_response = claim_future.result(), retire_future.result()
    if retire_response.status_code == 200:
        assert claim_response.status_code == 401
    else:
        assert retire_response.status_code == 409
        assert claim_response.status_code == 200 and claim_response.json()["job"]


def test_concurrent_retirement_requests_record_one_decision(env):
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: retire(env), range(2)))
    assert all(r.status_code == 200 for r in responses)
    assert responses[0].json() == responses[1].json()
    with env["app"].state.sessions() as db:
        assert len(db.scalars(select(Audit).where(Audit.action == "actor.deleted")).all()) == 1


def test_concurrent_approval_cannot_requeue_retired_actor(env, request_job):
    run = request_job().json()
    barrier = Barrier(2)

    def approve():
        barrier.wait()
        return env["client"].post(
            f"/api/v1/runs/{run['run_id']}/approve",
            headers={"X-Test-User": "approver"},
            json={"reason": "Synthetic concurrent approval verification"},
        )

    def retirement():
        barrier.wait()
        return retire(env)

    with ThreadPoolExecutor(max_workers=2) as pool:
        approve_future, retire_future = pool.submit(approve), pool.submit(retirement)
        approval, retirement = approve_future.result(), retire_future.result()
    assert retirement.status_code == 200 and approval.status_code in {200, 404, 409}
    with env["app"].state.sessions() as db:
        assert db.get(Run, run["run_id"]).status == "cancelled"
        assert db.get(Actor, env["actor"]) is None


def test_pending_actor_can_be_retired_without_ever_enrolling(real_actor):
    s = real_actor
    actor = (
        s["client"].post("/api/v1/actors", json={"hostname": "never-installed-host", "os": "linux"}).json()
    )
    package = s["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package",
        json={"api_url": "https://control.example.test", "include_enrollment": True},
    )
    assert package.status_code == 200
    response = s["client"].post(
        f"/api/v1/actors/{actor['id']}/retire", json={"hostname": actor["hostname"], "reason": REASON}
    )
    assert response.status_code == 200 and response.json()["deleted"] is True
    with s["app"].state.sessions() as db:
        assert db.scalar(select(Credential).where(Credential.actor_id == actor["id"])) is None
        assert db.scalar(select(Enrollment).where(Enrollment.actor_id == actor["id"])) is None
