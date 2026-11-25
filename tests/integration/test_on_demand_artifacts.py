"""Isolated protocol/evidence fixtures. No Atomic commands or host services execute."""

import base64
import copy
import io
import json
import time
import zipfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization

from apps.agent import artifact_execution
from apps.agent.artifacts import extract, payload_root, safe_path, verify_payload
from apps.agent.execution_broker import verify_job
from apps.api.app.models import Actor, AtomicTest, Attempt, Lease, Revision, Run
from apps.api.app.models import TestApproval as Approval
from apps.api.app.services.common import fingerprint
from tests.support.fixtures import fixture_result

GUID = "11111111-1111-4111-8111-111111111111"
ADMIN = {"X-Test-User": "admin"}


def prepare(env, **extra):
    test = env["client"].get(f"/api/v1/tests/{GUID}").json()
    return env["client"].post(
        f"/api/v1/tests/{GUID}/artifact/prepare",
        headers=ADMIN,
        json={"content_sha256": test["content_sha256"], "source_revision": test["revision"], **extra},
    )


def approve_files(env, artifact):
    test = env["client"].get(f"/api/v1/tests/{GUID}").json()
    response = env["client"].post(
        f"/api/v1/tests/{GUID}/review",
        headers=ADMIN,
        json={
            "content_sha256": test["content_sha256"],
            "source_revision": test["revision"],
            "artifact_digest": artifact["digest"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    )
    assert response.status_code == 200, response.text


@pytest.fixture
def delivery(env):
    env["settings"].approval_mode = "catalog"
    env["settings"].policy_file = ""
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.delivery_mode, actor.artifact_protocol, actor.revision = "on_demand", 1, ""
    response = prepare(env)
    assert response.status_code == 200, response.text
    env["artifact"] = response.json()["artifact"]
    approve_files(env, env["artifact"])
    private = serialization.load_pem_private_key(
        Path(env["settings"].signing_key_file).read_bytes(), password=None
    )
    env["public_key"] = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return env


def claim(env, request_job):
    requested = request_job()
    assert requested.status_code == 201, requested.text
    response = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={})
    assert response.status_code == 200, response.text
    return response.json()["job"]


def proof(job):
    return {"attempt_id": job["attempt_id"], "fence": job["fence"]}


def ready(env, job):
    return env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/ready", headers=env["agent"], json=proof(job)
    )


def download(env, job):
    return env["client"].get(
        f"/api/v1/agents/jobs/{job['run_id']}/artifact",
        headers={**env["agent"], "X-Job-Grant": job["download_grant"]},
    )


def receipt(env, job, status="purged"):
    return env["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/workspace",
        headers=env["agent"],
        json={**proof(job), "artifact_digest": job["snapshot"]["artifact"]["digest"], "status": status},
    )


def test_prepared_legacy_bundle_omits_empty_input_arguments(env):
    from apps.api.app.models import TestArtifact as Artifact

    response = prepare(env)
    assert response.status_code == 200, response.text
    with env["app"].state.sessions() as db:
        artifact = db.get(Artifact, response.json()["artifact"]["digest"])
        with zipfile.ZipFile(io.BytesIO(artifact.archive)) as bundle:
            atomic = yaml.safe_load(bundle.read("atomics/T1082/T1082.yaml"))["atomic_tests"][0]
    assert "input_arguments" not in atomic


def test_bundle_is_one_test_and_preparation_requires_execution_ticket(delivery, request_job, tmp_path):
    job = claim(delivery, request_job)
    archive = download(delivery, job)
    assert archive.status_code == 200, archive.text
    assert len(zipfile.ZipFile(io.BytesIO(archive.content)).namelist()) == 1
    config = {
        "actor_id": delivery["actor"],
        "os": "windows",
        "delivery_mode": "on_demand",
        "state_root": str(tmp_path),
        "profiles": [{**p, "validated": True} for p in delivery["profiles"]],
    }
    verify_job(job, config, delivery["public_key"], require_payload=False)
    with pytest.raises(ValueError, match="purpose"):
        verify_job(job, config, delivery["public_key"])
    source = tmp_path / "bundle.zip"
    source.write_bytes(archive.content)
    root = payload_root(config, job)
    root.parent.mkdir(parents=True)
    extract(source, root, job["snapshot"], delivery["public_key"])
    executable = ready(delivery, job).json()["job"]
    verify_job(executable, config, delivery["public_key"])
    assert download(delivery, job).status_code == 403
    yaml_file = root / "atomics/T1082/T1082.yaml"
    yaml_file.write_text("tampered")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_payload(root, job["snapshot"], delivery["public_key"])


def test_real_delivery_grants_accept_small_negative_clock_skew_without_expiry_leeway(
    delivery, request_job, tmp_path, monkeypatch
):
    job = claim(delivery, request_job)
    config = {
        "actor_id": delivery["actor"],
        "os": "windows",
        "delivery_mode": "on_demand",
        "state_root": str(tmp_path),
        "profiles": [{**p, "validated": True} for p in delivery["profiles"]],
    }
    server_now = time.time()

    class AgentClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(server_now - 2, tz)

    with monkeypatch.context() as clock:
        clock.setattr(jwt.api_jwt, "datetime", AgentClock)
        assert verify_job(job, config, delivery["public_key"], require_payload=False)
        claims = jwt.decode(
            job["download_grant"],
            delivery["public_key"],
            algorithms=["RS256"],
            issuer="atomic-control",
            audience=delivery["actor"],
        )
        assert claims["iat"] <= int(server_now) - 4
    archive = download(delivery, job)
    assert archive.status_code == 200
    source = tmp_path / "bundle.zip"
    source.write_bytes(archive.content)
    root = payload_root(config, job)
    root.parent.mkdir(parents=True)
    extract(source, root, job["snapshot"], delivery["public_key"])
    executable = ready(delivery, job).json()["job"]
    with monkeypatch.context() as clock:
        clock.setattr(jwt.api_jwt, "datetime", AgentClock)
        assert verify_job(executable, config, delivery["public_key"])
    claims = jwt.decode(
        executable["grant"],
        delivery["public_key"],
        algorithms=["RS256"],
        issuer="atomic-control",
        audience=delivery["actor"],
    )
    assert claims["exp"] == int(executable["lease_expires_at"])


@pytest.mark.parametrize("change", ["cancel", "revoke", "profile", "deadline", "snapshot"])
def test_changed_authorization_or_preparation_expiry_prevents_launch(delivery, request_job, change):
    job = claim(delivery, request_job)
    with delivery["app"].state.sessions() as db, db.begin():
        if change == "cancel":
            db.get(Run, job["run_id"]).cancel_requested = True
        elif change == "revoke":
            db.get(Approval, GUID).approved = False
        elif change == "profile":
            from apps.api.app.models import Profile

            db.get(Profile, job["snapshot"]["execution_profile_id"]).healthy = False
        elif change == "deadline":
            db.get(Attempt, job["attempt_id"]).preparation_deadline = time.time() - 1
        else:
            run = db.get(Run, job["run_id"])
            run.snapshot = {**run.snapshot, "hostname": "different"}
    assert ready(delivery, job).status_code == 409


def test_wrong_attempt_and_missing_credential_cannot_download(delivery, request_job):
    job = claim(delivery, request_job)
    path = f"/api/v1/agents/jobs/{job['run_id']}/artifact"
    assert delivery["client"].get(path, headers={"X-Job-Grant": job["download_grant"]}).status_code == 401
    assert (
        delivery["client"].get(path, headers={**delivery["agent"], "X-Job-Grant": "invalid"}).status_code
        == 403
    )
    assert (
        delivery["client"]
        .get(
            f"/api/v1/agents/jobs/{uuid4()}/artifact",
            headers={**delivery["agent"], "X-Job-Grant": job["download_grant"]},
        )
        .status_code
        == 403
    )


def test_result_does_not_release_actor_until_downloaded_files_removed(delivery, request_job):
    job = claim(delivery, request_job)
    assert ready(delivery, job).status_code == 200
    assert receipt(delivery, job, "purge_failed").status_code == 200
    result = delivery["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=delivery["agent"], json=fixture_result(job)
    )
    assert result.status_code == 200
    assert result.json()["status"] == "succeeded"
    assert (
        delivery["client"].post("/api/v1/agents/jobs/claim", headers=delivery["agent"], json={}).json()["job"]
        is None
    )
    actor = delivery["client"].get(f"/api/v1/actors/{delivery['actor']}").json()
    assert actor["workspace_status"] == "purge_failed"
    assert receipt(delivery, job).status_code == 200
    assert receipt(delivery, job).status_code == 200  # Lost acknowledgement retry.
    with delivery["app"].state.sessions() as db:
        assert db.get(Lease, delivery["actor"]) is None


def test_historical_cleanup_rehydrates_original_revision_after_catalog_change(delivery, request_job):
    job = claim(delivery, request_job)
    ready(delivery, job)
    receipt(delivery, job)
    delivery["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=delivery["agent"], json=fixture_result(job)
    )
    with delivery["app"].state.sessions() as db, db.begin():
        db.add(Revision(id="d" * 40))
        db.flush()
        test = db.get(AtomicTest, GUID)
        test.revision = "d" * 40
        test.definition = {**test.definition, "name": "New catalog version"}
        test.content_hash = fingerprint(test.definition)
        db.get(Approval, GUID).approved = False
    response = delivery["client"].post(
        f"/api/v1/runs/{job['run_id']}/cleanup",
        headers={"X-Test-User": "operator", "Idempotency-Key": str(uuid4())},
        json={"reason": "Authorized historical cleanup"},
    )
    assert response.status_code == 201, response.text
    cleanup = response.json()
    assert cleanup["snapshot"]["artifact"] == job["snapshot"]["artifact"]
    cleanup_job = (
        delivery["client"].post("/api/v1/agents/jobs/claim", headers=delivery["agent"], json={}).json()["job"]
    )
    assert cleanup_job["snapshot"]["source_revision"] == "c" * 40
    assert download(delivery, cleanup_job).status_code == 200
    delivery["client"].post(
        f"/api/v1/tests/{GUID}/revoke", headers=ADMIN, json={"reason": "Revoke historical artifact use"}
    )
    assert ready(delivery, cleanup_job).status_code == 409


def test_custom_asset_must_be_declared_supplied_and_bound_to_approval(env, request_job):
    with env["app"].state.sessions() as db, db.begin():
        test = db.get(AtomicTest, GUID)
        test.definition = {
            **test.definition,
            "executor": {
                **test.definition["executor"],
                "command": "& '#{PathToAtomicsFolder}/T1082/src/helper.ps1'",
            },
        }
        test.content_hash = fingerprint(test.definition)
    assert prepare(env).status_code == 422
    path = "atomics/T1082/src/helper.ps1"
    assert prepare(env, asset_paths=[path]).status_code == 422
    response = prepare(
        env,
        asset_paths=[path],
        files=[
            {"path": path, "content_base64": base64.b64encode(b"# Fixture bytes; never executed").decode()}
        ],
    )
    assert response.status_code == 200, response.text
    assert {f["path"] for f in response.json()["artifact"]["manifest"]["files"]} == {
        path,
        "atomics/T1082/T1082.yaml",
    }


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "atomics/../outside",
        "atomics/C:stream",
        "atomics/CON.txt",
        "atomics/a\\b",
        "atomics/a/",
        "atomics/a./b",
        "atomics//b",
        "/atomics/a",
    ],
)
def test_cross_platform_unsafe_paths_are_rejected(path):
    with pytest.raises(ValueError):
        safe_path(path)


def test_same_definition_at_different_revisions_gets_distinct_immutable_bundle(delivery):
    first = delivery["artifact"]
    with delivery["app"].state.sessions() as db, db.begin():
        db.add(Revision(id="e" * 40))
        db.flush()
        db.get(AtomicTest, GUID).revision = "e" * 40
    second = prepare(delivery).json()["artifact"]
    assert first["digest"] != second["digest"]
    assert first["manifest"]["revision"] != second["manifest"]["revision"]


def test_pipeline_purges_payload_before_retrying_lost_result_without_reexecution(
    delivery, request_job, tmp_path, monkeypatch
):
    job = claim(delivery, request_job)
    root = tmp_path / "jobs"
    root.mkdir()
    config = {
        "actor_id": delivery["actor"],
        "os": "windows",
        "delivery_mode": "on_demand",
        "state_root": str(root),
        "hostname": job["snapshot"]["hostname"],
        "revision": "",
        "os_version": "Windows fixture",
        "profiles": [{**p, "validated": True} for p in delivery["profiles"]],
    }
    calls = []

    class Client:
        fail_result = True

        def post(self, path, value):
            if path.endswith("/result") and self.fail_result:
                self.fail_result = False
                raise OSError("Disconnected result upload")
            response = delivery["client"].post("/api/v1/" + path, headers=delivery["agent"], json=value)
            assert response.status_code == 200, response.text
            return response.json()

        def download_artifact(self, value, destination, tick):
            tick()
            response = download(delivery, value)
            assert response.status_code == 200
            destination.write_bytes(response.content)

    broker = SimpleNamespace(
        config=config,
        root=root,
        journal=root / "active.json",
        public_key=delivery["public_key"],
        client=Client(),
        stop=__import__("threading").Event(),
    )
    monkeypatch.setattr("apps.agent.execution_broker.restrict_acl", lambda *args: None)
    monkeypatch.setattr(artifact_execution, "stop_execution", lambda *args: calls.append("stopped"))

    def executor(value):
        verify_job(value, config, delivery["public_key"])
        calls.append("fixture evidence only")
        return fixture_result(value)

    with pytest.raises(OSError, match="Disconnected"):
        artifact_execution.execute(broker, copy.deepcopy(job), executor)
    assert not payload_root(config, job).parent.exists()
    assert broker.journal.exists()
    assert artifact_execution.recover(broker)
    assert calls.count("fixture evidence only") == 1
    assert not broker.journal.exists()


def test_preparation_grant_cannot_submit_success_without_ready(delivery, request_job):
    job = claim(delivery, request_job)
    response = delivery["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=delivery["agent"], json=fixture_result(job)
    )
    assert response.status_code == 409


def test_legacy_inline_catalog_approval_prepares_automatically(env, request_job):
    env["settings"].approval_mode = "catalog"
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.delivery_mode, actor.artifact_protocol = "on_demand", 1
    response = request_job()
    assert response.status_code == 201, response.text
    assert response.json()["snapshot"]["file_plan"]["hash"]


@pytest.mark.parametrize("mutation", ["traversal", "link", "unlisted", "compressed", "duplicate"])
def test_malicious_archive_is_rejected_without_writing_outside_workspace(
    delivery, request_job, tmp_path, mutation
):
    from apps.agent.artifacts import sha256

    job = claim(delivery, request_job)
    original = zipfile.ZipFile(io.BytesIO(download(delivery, job).content))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.comment = original.comment
        for item in original.infolist():
            value = original.read(item)
            if mutation == "traversal":
                item.filename = "../outside.txt"
            elif mutation == "link":
                item.external_attr = 0o120777 << 16
            elif mutation == "unlisted":
                item.filename = "atomics/unlisted.txt"
            elif mutation == "compressed":
                item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, value)
            if mutation == "duplicate":
                archive.writestr(item, value)
    value = output.getvalue()
    snapshot = copy.deepcopy(job["snapshot"])
    snapshot["artifact"].update(digest=sha256(value), size=len(value))
    path = tmp_path / "malicious.zip"
    path.write_bytes(value)
    with pytest.raises(ValueError):
        extract(path, tmp_path / "payload", snapshot, delivery["public_key"])
    assert not (tmp_path / "outside.txt").exists()


def test_expired_lease_can_deliver_evidence_but_cannot_reexecute(delivery, request_job):
    job = claim(delivery, request_job)
    ready(delivery, job)
    with delivery["app"].state.sessions() as db, db.begin():
        db.get(Lease, delivery["actor"]).expires_at = time.time() - 1
    # Viewer polling marks the uncertain execution and retains the lock.
    delivery["client"].get(f"/api/v1/runs/{job['run_id']}")
    assert ready(delivery, job).status_code == 409
    assert receipt(delivery, job).status_code == 200
    result = delivery["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=delivery["agent"], json=fixture_result(job)
    )
    assert result.status_code == 200 and result.json()["status"] == "inconclusive"
    assert (
        delivery["client"].post("/api/v1/agents/jobs/claim", headers=delivery["agent"], json={}).json()["job"]
        is None
    )


def test_receipt_cannot_change_actor_attempt_or_digest(delivery, request_job):
    job = claim(delivery, request_job)
    response = delivery["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/workspace",
        headers=delivery["agent"],
        json={**proof(job), "artifact_digest": "f" * 64, "status": "purged"},
    )
    assert response.status_code == 403
    wrong = copy.deepcopy(job)
    wrong["fence"] = "a" * 64
    assert receipt(delivery, wrong).status_code == 409


def test_signature_and_wrong_definition_are_rejected(delivery, request_job, tmp_path):
    job = claim(delivery, request_job)
    path = tmp_path / "bundle.zip"
    path.write_bytes(download(delivery, job).content)
    for change in ["signature", "definition"]:
        snapshot = copy.deepcopy(job["snapshot"])
        if change == "signature":
            snapshot["artifact"]["signature"] = "invalid"
        else:
            snapshot["content_sha256"] = "f" * 64
        with pytest.raises((ValueError, jwt.PyJWTError)):
            extract(path, tmp_path / change, snapshot, delivery["public_key"])


def test_heartbeat_capability_drops_checkout_pin_without_changing_actor_identity(delivery):
    payload = {
        "hostname": "WIN-TEST-01",
        "os": "windows",
        "os_version": "Windows fixture",
        "agent_version": "0.2.0",
        "revision": "",
        "profiles": {p["id"]: True for p in delivery["profiles"]},
        "health": "healthy",
        "delivery_mode": "on_demand",
        "artifact_protocol": 1,
    }
    response = delivery["client"].post("/api/v1/agents/heartbeat", headers=delivery["agent"], json=payload)
    assert response.status_code == 200
    actor = delivery["client"].get(f"/api/v1/actors/{delivery['actor']}").json()
    assert actor["id"] == delivery["actor"] and actor["revision"] == "" and actor["artifact_protocol"] == 1


def test_on_demand_packages_include_protocol_without_catalog_or_git_requirement(env):
    response = env["client"].post(
        f"/api/v1/actors/{env['actor']}/agent-package",
        headers=ADMIN,
        json={"api_url": env["settings"].public_url, "delivery_mode": "on_demand"},
    )
    assert response.status_code == 200, response.text
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        config = json.loads(archive.read("AtomicControlAgent/agent.json"))
        assert config["delivery_mode"] == "on_demand"
        assert "AtomicControlAgent/catalog.json" not in archive.namelist()
        assert "AtomicControlAgent/runtime/apps/agent/artifact_execution.py" in archive.namelist()
        assert "AtomicControlAgent/runtime/apps/agent/windows_processes.py" in archive.namelist()
        assert "AtomicControlAgent/Update-Agent.py" in archive.namelist()
        assert "AtomicControlAgent/manifest.jwt" in archive.namelist()


def test_orphan_workspace_is_reported_and_blocks_dispatch(delivery, tmp_path):
    import threading

    from apps.agent.job_client import heartbeat_payload

    root = tmp_path / "jobs"
    orphan = root / "downloads" / str(uuid4())
    orphan.mkdir(parents=True)
    config = {
        "actor_id": delivery["actor"],
        "hostname": "WIN-TEST-01",
        "os": "windows",
        "os_version": "Windows fixture",
        "revision": "",
        "delivery_mode": "on_demand",
        "state_root": str(root),
        "profiles": [{**p, "validated": True} for p in delivery["profiles"]],
    }
    posts = []
    client = SimpleNamespace(post=lambda path, data: posts.append((path, data)))
    broker = SimpleNamespace(
        config=config, root=root, journal=root / "active.json", client=client, stop=threading.Event()
    )
    with pytest.raises(RuntimeError, match="Orphaned"):
        artifact_execution.check_orphans(broker)
    assert posts[0][1]["workspace_residue"] is True
    assert posts[0][1]["health"] == "degraded"
    response = delivery["client"].post(
        "/api/v1/agents/heartbeat", headers=delivery["agent"], json=heartbeat_payload(config)
    )
    assert response.status_code == 200
    actor = delivery["client"].get(f"/api/v1/actors/{delivery['actor']}").json()
    assert actor["workspace_status"] == "orphaned" and not actor["online"]
    assert orphan.exists()  # Unknown files are held for inspection, never guessed away.


def test_administrator_reconciliation_of_removal_hold_preserves_execution_outcome(delivery, request_job):
    from sqlalchemy import select

    from apps.api.app.models import Audit

    job = claim(delivery, request_job)
    ready(delivery, job)
    receipt(delivery, job, "purge_failed")
    delivery["client"].post(
        f"/api/v1/agents/jobs/{job['run_id']}/result", headers=delivery["agent"], json=fixture_result(job)
    )
    path = f"/api/v1/runs/{job['run_id']}/reconcile"
    reason = {"reason": "Verified the process tree and removed this attempt workspace"}
    assert delivery["client"].post(path, headers=ADMIN, json=reason).status_code == 409
    assert (
        delivery["client"]
        .post(path, headers={"X-Test-User": "operator"}, json={**reason, "workspace_removed": True})
        .status_code
        == 403
    )
    response = delivery["client"].post(path, headers=ADMIN, json={**reason, "workspace_removed": True})
    assert response.status_code == 200 and response.json()["status"] == "succeeded"
    with delivery["app"].state.sessions() as db:
        assert db.get(Lease, delivery["actor"]) is None
        assert (
            db.scalar(select(Audit).where(Audit.action == "artifact.workspace-admin-confirmed")) is not None
        )
