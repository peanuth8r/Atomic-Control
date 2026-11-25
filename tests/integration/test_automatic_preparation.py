"""Automatic packaging uses isolated catalogs and synthetic evidence, never host execution."""

import copy
import io
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select

from apps.agent.artifacts import extract, payload_root
from apps.agent.execution_broker import verify_job
from apps.api.app.catalog.serialization import definition_yaml
from apps.api.app.jobs import preparation
from apps.api.app.models import (
    Actor,
    ArtifactBuild,
    AtomicTest,
    Attempt,
    ExecutionBinding,
    FilePlan,
    Lease,
    Revision,
    Run,
    RunApproval,
    SourceBlob,
)
from apps.api.app.models import TestArtifact as Artifact
from apps.api.app.services.common import fingerprint
from tests.support.fixtures import fixture_result

GUID = "11111111-1111-4111-8111-111111111111"
ADMIN = {"X-Test-User": "admin"}
OP = {"X-Test-User": "operator"}


def approve(env, guid=GUID, **extra):
    test = env["client"].get(f"/api/v1/tests/{guid}").json()
    response = env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": test["content_sha256"],
            "source_revision": test["revision"],
            "risk_level": "low",
            "allowed_profiles": ["standard-user"],
            **extra,
        },
    )
    assert response.status_code == 200, response.text
    return env["client"].get(f"/api/v1/tests/{guid}").json()


@pytest.fixture
def auto(env):
    env["initial_policy"] = env["settings"].policy_file
    env["settings"].approval_mode, env["settings"].policy_file = "catalog", ""
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.delivery_mode, actor.artifact_protocol, actor.revision = "on_demand", 1, ""
    env["test"] = approve(env)
    env["plan"] = env["test"]["file_plan"]["hash"]
    return env


def request(env, guid=GUID):
    response = env["client"].post(
        "/api/v1/runs",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={
            "atomic_guid": guid,
            "actor_id": env["actor"],
            "execution_profile_id": env["profiles"][0]["id"],
            "reason": "Authorized isolated packaging protocol validation",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def claim(env):
    response = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={})
    assert response.status_code == 200, response.text
    return response.json()["job"]


def step(env):
    return preparation.process_once(env["app"].state.sessions, env["settings"])


def finish(env, job):
    proof = {"attempt_id": job["attempt_id"], "fence": job["fence"]}
    ready = env["client"].post(f"/api/v1/agents/jobs/{job['run_id']}/ready", headers=env["agent"], json=proof)
    assert ready.status_code == 200, ready.text
    receipt = env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/workspace",
        headers=env["agent"],
        json={**proof, "artifact_digest": job["snapshot"]["artifact"]["digest"], "status": "purged"},
    )
    assert receipt.status_code == 200, receipt.text
    response = env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=env["agent"], json=fixture_result(job)
    )
    assert response.status_code == 200, response.text


def test_approve_without_zip_then_single_run_packages_and_keeps_approval_snapshot_immutable(auto, tmp_path):
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 0
        assert db.get(FilePlan, auto["plan"])
    run = request(auto)
    original = copy.deepcopy(run["snapshot"])
    assert "file_plan" in original and "artifact" not in original
    assert claim(auto) is None
    with auto["app"].state.sessions() as db:
        assert db.get(Lease, auto["actor"]) is None
        assert db.scalar(select(func.count()).select_from(Attempt)) == 0
        assert db.get(Run, run["run_id"]).status == "preparing"
    assert step(auto)
    job = claim(auto)
    assert job["snapshot"]["artifact"]["manifest"]["guid"] == GUID
    with auto["app"].state.sessions() as db:
        stored = db.get(Run, run["run_id"])
        assert stored.snapshot == original and stored.snapshot_hash == fingerprint(original)
        assert db.get(RunApproval, stored.id).snapshot_hash == stored.snapshot_hash
        binding = db.get(ExecutionBinding, stored.id)
        assert binding.approved_snapshot_hash == stored.snapshot_hash
        assert binding.snapshot_hash != stored.snapshot_hash
    # Verify compatibility with the current installed artifact-protocol-v1 agent.
    private = serialization.load_pem_private_key(
        Path(auto["settings"].signing_key_file).read_bytes(), password=None
    )
    public = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    config = {
        "os": "windows",
        "actor_id": auto["actor"],
        "delivery_mode": "on_demand",
        "state_root": str(tmp_path),
        "profiles": [{**p, "validated": True} for p in auto["profiles"]],
    }
    verify_job(job, config, public, require_payload=False)
    download = auto["client"].get(
        f"/api/v1/agents/jobs/{job['run_id']}/artifact",
        headers={**auto["agent"], "X-Job-Grant": job["download_grant"]},
    )
    assert download.status_code == 200, download.text
    assert len(zipfile.ZipFile(io.BytesIO(download.content)).namelist()) == 1
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(download.content)
    root = payload_root(config, job)
    root.parent.mkdir(parents=True)
    extract(archive, root, job["snapshot"], public)
    ready = auto["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/ready",
        headers=auto["agent"],
        json={"attempt_id": job["attempt_id"], "fence": job["fence"]},
    )
    assert ready.status_code == 200, ready.text
    verify_job(ready.json()["job"], config, public)
    finish(auto, job)
    final = auto["client"].get(f"/api/v1/runs/{run['run_id']}").json()
    assert final["status"] == "succeeded" and final["workspace_status"] == "purged"
    assert (
        final["snapshot"] == original
        and final["execution_artifact"]["digest"] == job["snapshot"]["artifact"]["digest"]
    )


def add_test(env):
    guid = str(uuid4())
    with env["app"].state.sessions() as db, db.begin():
        original = db.get(AtomicTest, GUID)
        definition = {**original.definition, "auto_generated_guid": guid, "name": "Second revision fixture"}
        db.add(Revision(id="d" * 40))
        db.flush()
        db.add(
            AtomicTest(
                guid=guid,
                technique=original.technique,
                name=definition["name"],
                definition=definition,
                content_hash=fingerprint(definition),
                revision="d" * 40,
                catalog_source="test-fixture",
                simulated=False,
                active=True,
            )
        )
    approve(env, guid)
    return guid


def batch(env, guids, failure_policy="continue"):
    body = {"execution_profile_id": env["profiles"][0]["id"], "atomic_guids": guids}
    preview = env["client"].post(f"/api/v1/actors/{env['actor']}/queue/preview", headers=OP, json=body)
    assert preview.status_code == 200, preview.text
    assert preview.json()["eligible_count"] == len(guids)
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/queue",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={
            **body,
            "preview_hash": preview.json()["preview_hash"],
            "name": "Automatic bundle fixtures",
            "reason": "Authorized isolated packaging protocol validation",
            "failure_policy": failure_policy,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_queue_prepares_only_head_and_preserves_mixed_revision_order(auto):
    second = add_test(auto)
    queue = batch(auto, [GUID, second])
    first, later = [item["run_id"] for item in queue["items"]]
    assert claim(auto) is None
    assert step(auto)
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(ArtifactBuild)) == 1
        assert db.get(Run, later).status == "queued"
    job = claim(auto)
    assert job["run_id"] == first
    assert not step(auto)  # No prefetch to actors or packaging of the next head during execution.
    finish(auto, job)
    assert claim(auto) is None
    assert step(auto)
    next_job = claim(auto)
    assert next_job["run_id"] == later and next_job["snapshot"]["source_revision"] == "d" * 40


@pytest.mark.parametrize("policy,paused", [("continue", False), ("pause", True)])
def test_operational_packaging_failure_obeys_queue_policy_without_actor_attempt(
    auto, monkeypatch, policy, paused
):
    second = add_test(auto)
    queue = batch(auto, [GUID, second], policy)
    original = preparation.content

    def unavailable(sessions, key, settings):
        if key == auto["plan"]:
            raise OSError("Isolated transport failure")
        return original(sessions, key, settings)

    monkeypatch.setattr(preparation, "content", unavailable)
    for _ in range(3):
        step(auto)
        with auto["app"].state.sessions() as db, db.begin():
            build = db.get(ArtifactBuild, auto["plan"])
            build.retry_at = 0
    step(auto)  # Record the failed item and apply Continue/Pause.
    status = auto["client"].get(f"/api/v1/run-batches/{queue['id']}").json()
    assert status["items"][0]["status"] == "preparation_failed" and status["paused"] is paused
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Attempt)) == 0
        assert db.get(Lease, auto["actor"]) is None
    if not paused:
        step(auto)
        assert claim(auto)["run_id"] == queue["items"][1]["run_id"]


def test_cancel_and_pause_during_preparation_never_dispatch(auto):
    queue = batch(auto, [GUID])
    run_id = queue["items"][0]["run_id"]
    assert claim(auto) is None
    auto["client"].post(f"/api/v1/run-batches/{queue['id']}/pause", headers=OP, json={})
    assert not step(auto)
    assert claim(auto) is None
    auto["client"].post(f"/api/v1/run-batches/{queue['id']}/resume", headers=OP, json={})
    assert step(auto)
    auto["client"].post(
        f"/api/v1/runs/{run_id}/cancel", headers=OP, json={"reason": "Cancel isolated preparation fixture"}
    )
    assert claim(auto) is None
    assert auto["client"].get(f"/api/v1/runs/{run_id}").json()["status"] == "cancelled"


def test_revocation_between_build_and_dispatch_blocks_work(auto):
    run = request(auto)
    step(auto)
    auto["client"].post(
        f"/api/v1/tests/{GUID}/revoke", headers=ADMIN, json={"reason": "Revoke isolated fixture approval"}
    )
    step(auto)
    assert claim(auto) is None
    assert auto["client"].get(f"/api/v1/runs/{run['run_id']}").json()["status"] == "rejected"


def test_expired_worker_lease_is_recovered_without_duplicating_build_or_execution(auto):
    run = request(auto)
    claim(auto)
    with auto["app"].state.sessions() as db, db.begin():
        build = db.get(ArtifactBuild, auto["plan"])
        build.status, build.owner, build.lease_expires_at, build.attempts = (
            "building",
            str(uuid4()),
            time.time() - 1,
            1,
        )
    assert step(auto)
    job = claim(auto)
    assert job["run_id"] == run["run_id"]
    with auto["app"].state.sessions() as db:
        assert db.get(ArtifactBuild, auto["plan"]).attempts == 2
        assert db.scalar(select(func.count()).select_from(Artifact)) == 1
        assert db.scalar(select(func.count()).select_from(Attempt)) == 1


def test_multiple_workers_share_one_packaging_result(auto):
    request(auto)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: step(auto), range(2)))
    assert sum(results) == 1
    with auto["app"].state.sessions() as db:
        assert db.get(ArtifactBuild, auto["plan"]).attempts == 1
        assert db.scalar(select(func.count()).select_from(Artifact)) == 1


def test_cleanup_uses_original_execution_binding_after_catalog_update(auto):
    run = request(auto)
    step(auto)
    job = claim(auto)
    finish(auto, job)
    with auto["app"].state.sessions() as db, db.begin():
        db.add(Revision(id="e" * 40))
        db.flush()
        test = db.get(AtomicTest, GUID)
        test.revision = "e" * 40
        test.definition = {**test.definition, "name": "Updated catalog fixture"}
        test.content_hash = fingerprint(test.definition)
    response = auto["client"].post(
        f"/api/v1/runs/{run['run_id']}/cleanup",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={"reason": "Authorized original cleanup fixture"},
    )
    assert response.status_code == 201, response.text
    cleanup = claim(auto)
    assert cleanup["snapshot"]["artifact"] == job["snapshot"]["artifact"]
    assert cleanup["snapshot"]["source_revision"] == "c" * 40


def test_integrity_failure_holds_queue_and_starts_no_attempt(auto):
    queue = batch(auto, [GUID, add_test(auto)])
    with auto["app"].state.sessions() as db, db.begin():
        plan = db.get(FilePlan, auto["plan"])
        blob = db.get(SourceBlob, plan.manifest["files"][0]["sha256"])
        blob.content = b"corrupt isolated source blob"
    assert not step(auto)
    step(auto)
    status = auto["client"].get(f"/api/v1/run-batches/{queue['id']}").json()
    assert status["paused"] and status["items"][0]["status"] == "rejected"
    assert claim(auto) is None
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Attempt)) == 0


def test_optional_per_run_approval_never_changes_when_packaging_finishes(auto):
    auto["settings"].approval_mode, auto["settings"].policy_file = "per_run", auto["initial_policy"]
    run = request(auto)
    assert run["status"] == "pending_approval" and not step(auto)
    response = auto["client"].post(
        f"/api/v1/runs/{run['run_id']}/approve",
        headers={"X-Test-User": "approver"},
        json={"reason": "Explicit authorized fixture approval"},
    )
    assert response.status_code == 200, response.text
    assert step(auto)
    with auto["app"].state.sessions() as db, db.begin():
        db.get(RunApproval, run["run_id"]).expires_at = time.time() - 1
    assert claim(auto) is None
    with auto["app"].state.sessions() as db:
        stored = db.get(Run, run["run_id"])
        assert stored.status == "pending_approval" and stored.snapshot == run["snapshot"]
        assert db.get(Lease, auto["actor"]) is None


@pytest.mark.parametrize("action", ["cancel", "pause"])
def test_cancel_or_pause_while_worker_is_building_cannot_dispatch(auto, monkeypatch, action):
    queue = batch(auto, [GUID])
    original = preparation.content

    def interrupt(sessions, key, settings):
        value = original(sessions, key, settings)
        response = auto["client"].post(f"/api/v1/run-batches/{queue['id']}/{action}", headers=OP, json={})
        assert response.status_code == 200
        return value

    monkeypatch.setattr(preparation, "content", interrupt)
    assert step(auto)  # A valid shared cache entry may still finish.
    assert claim(auto) is None
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Attempt)) == 0
        assert db.scalar(select(func.count()).select_from(ExecutionBinding)) == 0


def test_old_worker_cannot_publish_after_its_lease_was_reclaimed(auto, monkeypatch):
    request(auto)
    original = preparation.content

    def reclaim(sessions, key, settings):
        value = original(sessions, key, settings)
        with preparation.transaction(sessions) as db:
            build = db.get(ArtifactBuild, key)
            build.owner, build.lease_expires_at = str(uuid4()), time.time() + 30
        return value

    monkeypatch.setattr(preparation, "content", reclaim)
    assert not step(auto)
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 0
        assert db.scalar(select(func.count()).select_from(Attempt)) == 0


def test_shared_file_plan_is_built_once_for_multiple_actors(auto):
    from apps.api.app.models import Profile

    run = request(auto)
    with auto["app"].state.sessions() as db, db.begin():
        actor = Actor(
            hostname="SECOND-FIXTURE",
            delivery_mode="on_demand",
            artifact_protocol=1,
            revision="",
            health="healthy",
            last_heartbeat=time.time(),
            simulated=False,
            os="windows",
        )
        db.add(actor)
        db.flush()
        profile = Profile(
            actor_id=actor.id,
            profile_key="standard-user",
            display_name="Fixture profile",
            account="SECOND-FIXTURE\\atomic-user",
            expected_sid="S-1-5-21-1-2-3-1001",
            privilege="standard",
            healthy=True,
        )
        db.add(profile)
        db.flush()
        actor_id, profile_id = actor.id, profile.id
    response = auto["client"].post(
        "/api/v1/runs",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={
            "atomic_guid": GUID,
            "actor_id": actor_id,
            "execution_profile_id": profile_id,
            "reason": "Authorized isolated shared packaging fixture",
        },
    )
    assert response.status_code == 201, response.text
    assert step(auto)
    assert not step(auto)  # Only sealing per-run bindings remains; no second build.
    with auto["app"].state.sessions() as db:
        assert db.get(ArtifactBuild, auto["plan"]).attempts == 1
        assert db.scalar(select(func.count()).select_from(Artifact)) == 1
        one, two = (
            db.get(ExecutionBinding, run["run_id"]),
            db.get(ExecutionBinding, response.json()["run_id"]),
        )
        assert one.snapshot["artifact"] == two.snapshot["artifact"]
        assert one.snapshot_hash != two.snapshot_hash


def test_retry_preparation_creates_a_new_audited_request_but_cannot_repeat_execution(auto, monkeypatch):
    run = request(auto)
    original = preparation.content
    monkeypatch.setattr(
        preparation, "content", lambda *args: (_ for _ in ()).throw(OSError("Isolated failure"))
    )
    for _ in range(3):
        step(auto)
        with auto["app"].state.sessions() as db, db.begin():
            db.get(ArtifactBuild, auto["plan"]).retry_at = 0
    step(auto)
    monkeypatch.setattr(preparation, "content", original)
    response = auto["client"].post(
        f"/api/v1/runs/{run['run_id']}/retry-preparation",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={"reason": "Retry after fixing the isolated source outage"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["run_id"] != run["run_id"]
    assert step(auto)
    job = claim(auto)
    assert job["run_id"] == response.json()["run_id"]
    forbidden = auto["client"].post(
        f"/api/v1/runs/{job['run_id']}/retry-preparation",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={"reason": "Never repeat an actor attempt automatically"},
    )
    assert forbidden.status_code == 409


def test_background_worker_starts_with_api_lifespan_and_builds_without_manual_endpoint(auto):
    run = request(auto)
    with auto["client"]:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with auto["app"].state.sessions() as db:
                ready = db.get(ExecutionBinding, run["run_id"]) is not None
            if ready:
                break
            time.sleep(0.05)
        assert ready
        assert auto["app"].state.preparation_worker.is_alive()
    assert not auto["app"].state.preparation_worker.is_alive()


def test_migration_converts_exact_approval_and_preserves_existing_queued_snapshot(env):
    import os
    import subprocess
    import sys

    from apps.api.app.models import TestApproval as Review

    env["settings"].approval_mode, env["settings"].policy_file = "catalog", ""
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.delivery_mode, actor.artifact_protocol = "on_demand", 1
    test = env["client"].get(f"/api/v1/tests/{GUID}").json()
    response = env["client"].post(
        f"/api/v1/tests/{GUID}/artifact/prepare",
        headers=ADMIN,
        json={"content_sha256": test["content_sha256"], "source_revision": test["revision"]},
    )
    assert response.status_code == 200, response.text
    descriptor = response.json()["artifact"]
    response = env["client"].post(
        f"/api/v1/tests/{GUID}/review",
        headers=ADMIN,
        json={
            "content_sha256": test["content_sha256"],
            "source_revision": test["revision"],
            "artifact_digest": descriptor["digest"],
            "risk_level": "low",
            "allowed_profiles": ["standard-user"],
        },
    )
    assert response.status_code == 200
    old = request(env)
    assert "artifact" in old["snapshot"] and "file_plan" not in old["snapshot"]
    migration_env = {**os.environ, "ATOMIC_DATABASE_URL": env["settings"].database_url}
    for command in [("stamp", "head"), ("downgrade", "fc129a8d4530"), ("upgrade", "head")]:
        subprocess.run(
            [sys.executable, "-m", "alembic", *command],
            env=migration_env,
            capture_output=True,
            text=True,
            check=True,
        )
    with env["app"].state.sessions() as db:
        review = db.get(Review, GUID)
        assert review.plan_hash
        assert db.get(ArtifactBuild, review.plan_hash).status == "ready"
        assert db.get(Run, old["run_id"]).snapshot == old["snapshot"]
    old_job = claim(env)
    assert old_job["snapshot"] == old["snapshot"]
    finish(env, old_job)
    new = request(env)
    assert "file_plan" in new["snapshot"] and "artifact" not in new["snapshot"]
    new_job = claim(env)
    assert new_job["snapshot"]["artifact"] == descriptor


def test_retry_submission_replay_does_not_reset_a_later_failed_shared_build(auto, monkeypatch):
    run = request(auto)
    monkeypatch.setattr(
        preparation, "content", lambda *args: (_ for _ in ()).throw(OSError("Isolated source outage"))
    )

    def fail_build():
        for _ in range(3):
            step(auto)
            with auto["app"].state.sessions() as db, db.begin():
                db.get(ArtifactBuild, auto["plan"]).retry_at = 0
        step(auto)

    fail_build()
    path = f"/api/v1/runs/{run['run_id']}/retry-preparation"
    headers = {**OP, "Idempotency-Key": str(uuid4())}
    body = {"reason": "Retry isolated unavailable source"}
    first = auto["client"].post(path, headers=headers, json=body)
    assert first.status_code == 201
    fail_build()
    replay = auto["client"].post(path, headers=headers, json=body)
    assert replay.status_code == 201 and replay.json()["run_id"] == first.json()["run_id"]
    with auto["app"].state.sessions() as db:
        assert db.get(ArtifactBuild, auto["plan"]).status == "failed"
        assert db.scalar(select(func.count()).select_from(Run)) == 2


def test_generated_single_test_yaml_can_be_recovered_without_fetching_whole_upstream_yaml(auto):
    request(auto)
    with auto["app"].state.sessions() as db, db.begin():
        plan = db.get(FilePlan, auto["plan"])
        blob = db.get(SourceBlob, plan.manifest["files"][0]["sha256"])
        db.delete(blob)
    assert step(auto)
    job = claim(auto)
    assert len(job["snapshot"]["artifact"]["manifest"]["files"]) == 1


@pytest.mark.parametrize("missing_blob", [False, True])
def test_reapproval_refreshes_old_yaml_without_rewriting_historical_plans(auto, monkeypatch, missing_blob):
    # Reproduce the stored plan made by the old renderer, then restore production
    # rendering before the administrator approves again. No Atomic command runs.
    with monkeypatch.context() as patch:
        patch.setattr(
            "apps.api.app.services.file_plans.definition_yaml",
            lambda definition: definition_yaml(definition, legacy=True),
        )
        old = approve(auto)
    old_hash = old["file_plan"]["hash"]
    old_manifest = copy.deepcopy(old["file_plan"]["manifest"])
    before = request(auto)
    with auto["app"].state.sessions() as db, db.begin():
        blob = db.get(SourceBlob, old_manifest["files"][0]["sha256"])
        assert yaml.safe_load(blob.content)["atomic_tests"][0]["input_arguments"] == {}
        if missing_blob:
            db.delete(blob)
    # Historical restoration must match the original manifest, including when
    # the content store must reconstruct YAML from the retained definition.
    _, _, archive = preparation.content(auto["app"].state.sessions, old_hash, auto["settings"])
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert (
            yaml.safe_load(bundle.read("atomics/T1082/T1082.yaml"))["atomic_tests"][0]["input_arguments"]
            == {}
        )
    updated = approve(auto)
    new_hash = updated["file_plan"]["hash"]
    assert new_hash != old_hash
    assert updated["content_sha256"] == old["content_sha256"]
    assert updated["definition"] == old["definition"]
    assert updated["risk_level"] == old["risk_level"]
    assert updated["allowed_profiles"] == old["allowed_profiles"]
    assert approve(auto)["file_plan"]["hash"] == new_hash  # Current plans are reusable.
    after = request(auto)
    assert after["snapshot"]["file_plan"]["hash"] == new_hash
    with auto["app"].state.sessions() as db:
        assert db.get(FilePlan, old_hash).manifest == old_manifest
        assert db.get(Run, before["run_id"]).snapshot == before["snapshot"]
    _, _, archive = preparation.content(auto["app"].state.sessions, new_hash, auto["settings"])
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert (
            "input_arguments"
            not in yaml.safe_load(bundle.read("atomics/T1082/T1082.yaml"))["atomic_tests"][0]
        )


def test_requester_permission_revocation_during_actor_download_prevents_execution_ticket(auto):
    from apps.api.app.models import UserAccessState

    request(auto)
    step(auto)
    job = claim(auto)
    with auto["app"].state.sessions() as db, db.begin():
        db.add(
            UserAccessState(
                subject="dev:operator",
                blocked=True,
                invalid_before=int(time.time()),
                updated_at=time.time(),
                updated_by="dev:admin",
            )
        )
    response = auto["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/ready",
        headers=auto["agent"],
        json={"attempt_id": job["attempt_id"], "fence": job["fence"]},
    )
    assert response.status_code == 403
    with auto["app"].state.sessions() as db:
        assert db.get(Attempt, job["attempt_id"]).execution_authorized_at is None


def test_custom_supporting_file_is_approved_inline_and_packaged_only_for_execution(auto):
    import base64

    path = "atomics/T1082/src/fixture.txt"
    raw = b"Isolated supporting data; never executed"
    with auto["app"].state.sessions() as db, db.begin():
        test = db.get(AtomicTest, GUID)
        test.definition = {
            **test.definition,
            "executor": {
                **test.definition["executor"],
                "command": "Get-Content '#{PathToAtomicsFolder}/T1082/src/fixture.txt'",
            },
        }
        test.content_hash = fingerprint(test.definition)
    approved = approve(
        auto, asset_paths=[path], files=[{"path": path, "content_base64": base64.b64encode(raw).decode()}]
    )
    assert approved["file_plan"] and approved["artifact"] is None
    with auto["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 0
    request(auto)
    assert step(auto)
    job = claim(auto)
    download = auto["client"].get(
        f"/api/v1/agents/jobs/{job['run_id']}/artifact",
        headers={**auto["agent"], "X-Job-Grant": job["download_grant"]},
    )
    assert download.status_code == 200
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        assert set(archive.namelist()) == {path, "atomics/T1082/T1082.yaml"}
        assert archive.read(path) == raw
