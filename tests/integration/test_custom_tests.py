"""Custom submission, review and signed delivery; no Atomic commands execute."""

import base64
import io
import zipfile
from uuid import uuid4

import pytest
import yaml
from sqlalchemy import func, select

from apps.api.app.models import Actor, AtomicTest, Audit, CustomTestSubmission, Run, SourceBlob
from apps.api.app.models import TestApproval as Approval

PATH = "/api/v1/catalog/custom-tests"
ADMIN = {"X-Test-User": "admin"}
OP = {"X-Test-User": "operator"}


def document(guid=None, **extra):
    test = {
        "name": "Custom hostname fixture",
        "auto_generated_guid": guid or str(uuid4()),
        "description": "Isolated submission fixture. Never executed.",
        "supported_platforms": ["windows"],
        "executor": {"name": "command_prompt", "command": "echo fixture\n"},
        **extra,
    }
    return {
        "attack_technique": "T1082",
        "display_name": "System Information Discovery",
        "atomic_tests": [test],
    }


def submit(env, doc=None, key=None, user="operator", **extra):
    return env["client"].post(
        PATH,
        headers={"X-Test-User": user, "Idempotency-Key": key or str(uuid4())},
        json={"content": yaml.safe_dump(doc or document()), **extra},
    )


def review(env, guid):
    test = env["client"].get(f"/api/v1/tests/{guid}").json()
    return env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": test["content_sha256"],
            "source_revision": test["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    )


def request(env, guid):
    return env["client"].post(
        "/api/v1/runs",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={
            "atomic_guid": guid,
            "actor_id": env["actor"],
            "execution_profile_id": env["profiles"][0]["id"],
        },
    )


def test_submission_creates_only_unapproved_content_and_cannot_execute(env):
    response = submit(env)
    assert response.status_code == 201, response.text
    receipt = response.json()
    assert receipt["status"] == "submitted" and receipt["source"] == "custom"
    assert receipt["revision_kind"] == "content" and len(receipt["revision"]) == 40
    assert receipt["submitted_by"] == "dev:operator" and not receipt["replayed"]
    guid = receipt["tests"][0]["guid"]
    detail = env["client"].get(f"/api/v1/tests/{guid}").json()
    assert detail["catalog_source"] == "custom" and not detail["approved"]
    assert detail["execution_ready"] and detail["allowed_profiles"] == []
    assert all(
        t["guid"] != guid for t in env["client"].get("/api/v1/tests?approved_only=true").json()["items"]
    )
    assert request(env, guid).json()["error"]["code"] == "test_unapproved"
    with env["app"].state.sessions() as db:
        assert db.get(Approval, guid) is None
        assert db.scalar(select(func.count()).select_from(Run)) == 0
        assert (
            db.scalar(select(Audit).where(Audit.action == "catalog.custom-submitted")).identity
            == "dev:operator"
        )


@pytest.mark.parametrize("user,code", [("viewer", 403), ("approver", 403), ("operator", 201), ("admin", 201)])
def test_submission_roles(env, user, code):
    assert submit(env, user=user).status_code == code


def test_missing_authentication_and_key(env):
    assert (
        env["client"].post(PATH, headers=OP, json={"content": yaml.safe_dump(document())}).status_code == 422
    )
    env["app"].dependency_overrides.clear()
    assert (
        env["client"]
        .post(PATH, headers={"Idempotency-Key": "no-auth"}, json={"content": yaml.safe_dump(document())})
        .status_code
        == 401
    )


def test_idempotent_retry_never_resets_approval_or_changes_content(env):
    doc = document()
    original = submit(env, doc, key="stable").json()
    guid = original["tests"][0]["guid"]
    assert review(env, guid).status_code == 200
    again = submit(env, doc, key="stable")
    assert again.status_code == 201 and again.json()["replayed"]
    assert again.json()["id"] == original["id"]
    assert env["client"].get(f"/api/v1/tests/{guid}").json()["approved"]
    doc["atomic_tests"][0]["executor"]["command"] = "echo changed\n"
    assert submit(env, doc, key="stable").json()["error"]["code"] == "idempotency_conflict"
    assert submit(env, doc).json()["error"]["code"] == "custom_guid_conflict"
    with env["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(CustomTestSubmission)) == 1
        assert db.get(AtomicTest, guid).definition["executor"]["command"] == "echo fixture\n"


def test_existing_guid_collision_rolls_back_whole_document(env):
    existing = "11111111-1111-4111-8111-111111111111"
    with env["app"].state.sessions() as db:
        before = db.get(AtomicTest, existing).content_hash
    doc = document()
    fresh = doc["atomic_tests"][0]["auto_generated_guid"]
    doc["atomic_tests"].append(document(existing)["atomic_tests"][0])
    response = submit(env, doc)
    assert response.status_code == 409 and response.json()["error"]["code"] == "custom_guid_conflict"
    with env["app"].state.sessions() as db:
        assert db.get(AtomicTest, fresh) is None
        assert db.get(AtomicTest, existing).content_hash == before and db.get(Approval, existing).approved
        assert db.scalar(select(func.count()).select_from(CustomTestSubmission)) == 0


@pytest.mark.parametrize(
    "content",
    [
        "attack_technique: T1082\nattack_technique: T1082\n",
        "x: &ref [*ref]",
        "!!python/object/apply:os.system [echo nope]",
        "atomic_tests: []",
    ],
)
def test_invalid_yaml_has_no_catalog_effects(env, content):
    response = env["client"].post(
        PATH, headers={**OP, "Idempotency-Key": "invalid"}, json={"content": content}
    )
    assert response.status_code == 422
    with env["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(CustomTestSubmission)) == 0


@pytest.mark.parametrize(
    "file",
    [
        {"path": "../outside.sh", "content_base64": "YQ=="},
        {"path": "atomics/T1005/src/file.sh", "content_base64": "YQ=="},
        {"path": "atomics/T1082/T1082.yaml", "content_base64": "YQ=="},
        {"path": "atomics/T1082/T1082.yaml/nested.txt", "content_base64": "YQ=="},
        {"path": "atomics/T1082/src/file.sh", "content_base64": "not-base64!"},
    ],
)
def test_bad_supporting_files_are_atomic(env, file):
    response = submit(env, files=[file])
    assert response.status_code == 422, response.text
    with env["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(CustomTestSubmission)) == 0
        assert db.scalar(select(func.count()).select_from(SourceBlob)) == 0


def test_unknown_fields_and_byte_limits(env):
    assert submit(env, approved=True).status_code == 422
    assert submit(env, source_revision="f" * 40).status_code == 422
    assert submit(env, filename="../custom.yaml").status_code == 422
    doc = document(description="é" * 510_000)
    assert submit(env, doc).status_code == 422


def test_retained_assets_review_and_protocol_v1_delivery(env, monkeypatch, tmp_path):
    from apps.api.app.jobs import preparation
    from apps.api.app.services.common import fingerprint

    env["settings"].approval_mode = "catalog"
    env["settings"].policy_file = ""
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.delivery_mode, actor.artifact_protocol, actor.revision = "on_demand", 1, ""
    path = "atomics/T1082/src/custom.txt"
    raw = b"fixture payload bytes, never executed"
    doc = document(
        input_arguments={
            "file": {
                "description": "Fixture asset",
                "type": "path",
                "default": "#{PathToAtomicsFolder}/T1082/src/custom.txt",
            }
        }
    )
    response = submit(env, doc, files=[{"path": path, "content_base64": base64.b64encode(raw).decode()}])
    assert response.status_code == 201, response.text
    receipt = response.json()
    guid = receipt["tests"][0]["guid"]
    metadata = env["client"].get(f"/api/v1/tests/{guid}/artifact").json()
    assert metadata["submitted_files"] == receipt["files"] and metadata["suggested_assets"] == [path]
    assert metadata["file_plan"] is None

    def no_fetch(*args, **kwargs):
        if args[1]:
            raise AssertionError("Custom source must not be fetched from GitHub")
        return {}

    monkeypatch.setattr("apps.api.app.services.file_plans.fetch_assets", no_fetch)
    monkeypatch.setattr("apps.api.app.jobs.preparation.fetch_assets", no_fetch)
    # Normal UI-style review sends declared paths and no replacement files.
    test = env["client"].get(f"/api/v1/tests/{guid}").json()
    approved = env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": test["content_sha256"],
            "source_revision": test["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
            "asset_paths": [path],
            "files": [],
        },
    )
    assert approved.status_code == 200, approved.text
    run = request(env, guid)
    assert run.status_code == 201, run.text
    assert preparation.process_once(env["app"].state.sessions, env["settings"])
    job = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={}).json()["job"]
    assert job["snapshot"]["source_revision"] == receipt["revision"]
    manifest = job["snapshot"]["artifact"]["manifest"]
    assert manifest["definition_hash"] == fingerprint(test["definition"])
    download = env["client"].get(
        f"/api/v1/agents/jobs/{job['run_id']}/artifact",
        headers={**env["agent"], "X-Job-Grant": job["download_grant"]},
    )
    assert download.status_code == 200
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    from apps.agent.artifacts import extract
    from apps.agent.execution_broker import verify_job

    signer = serialization.load_pem_private_key(
        Path(env["settings"].signing_key_file).read_bytes(), password=None
    )
    public = (
        signer.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    verify_job(
        job,
        {
            "actor_id": env["actor"],
            "os": "windows",
            "delivery_mode": "on_demand",
            "state_root": str(tmp_path),
            "profiles": [{**profile, "validated": True} for profile in env["profiles"]],
        },
        public,
        require_payload=False,
    )
    archive = tmp_path / "custom.zip"
    archive.write_bytes(download.content)
    extract(archive, tmp_path / "verified", job["snapshot"], public)
    assert (tmp_path / "verified" / path).read_bytes() == raw
    with zipfile.ZipFile(io.BytesIO(download.content)) as bundle:
        assert set(bundle.namelist()) == {path, "atomics/T1082/T1082.yaml"}
        assert bundle.read(path) == raw
        assert (
            yaml.safe_load(bundle.read("atomics/T1082/T1082.yaml"))["atomic_tests"][0]["auto_generated_guid"]
            == guid
        )


def test_custom_revisions_are_not_host_checkout_options(env):
    from types import SimpleNamespace

    from fastapi import HTTPException

    from apps.api.app.services.catalog_deployments import desired, options

    added = submit(env).json()
    revision = added["revision"]
    assert (
        revision not in env["client"].get("/api/v1/agents/package-options", headers=ADMIN).json()["revisions"]
    )
    with env["app"].state.sessions() as db:
        actor = db.get(Actor, env["actor"])
        linux = SimpleNamespace(id=actor.id, hostname=actor.hostname, os="linux")
        assert revision not in [entry["revision"] for entry in options(db, linux)]
        with pytest.raises(HTTPException) as caught:
            desired(db, actor, revision)
        assert caught.value.detail["code"] == "custom_test_delivery"
    guid = added["tests"][0]["guid"]
    assert review(env, guid).status_code == 200
    assert request(env, guid).json()["error"]["code"] == "custom_test_delivery"


def test_concurrent_retries_create_one_submission(env):
    from concurrent.futures import ThreadPoolExecutor

    doc = document()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: submit(env, doc, key="concurrent"), range(2)))
    assert [result.status_code for result in results] == [201, 201]
    assert {result.json()["replayed"] for result in results} == {False, True}
    assert len({result.json()["id"] for result in results}) == 1


def test_retained_file_corruption_blocks_review(env):
    file = {"path": "atomics/T1082/src/retained.txt", "content_base64": "Zml4dHVyZQ=="}
    response = submit(env, files=[file]).json()
    with env["app"].state.sessions() as db, db.begin():
        db.get(SourceBlob, response["files"][0]["sha256"]).content = b"changed"
    rejected = review(env, response["tests"][0]["guid"])
    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "custom_source_unavailable"
    with env["app"].state.sessions() as db:
        assert db.get(Approval, response["tests"][0]["guid"]) is None


def test_custom_asset_body_can_exceed_ordinary_api_limit(env):
    raw = b"A" * 220_000
    file = {"path": "atomics/T1082/src/bounded.txt", "content_base64": base64.b64encode(raw).decode()}
    response = submit(env, files=[file])
    assert response.status_code == 201, response.text
    assert response.json()["files"][0]["size"] == len(raw)


@pytest.mark.parametrize(
    "paths",
    [
        ["atomics/T1082/src/file.txt", "atomics/T1082/src/file.txt"],
        ["atomics/T1082/src/file.txt", "atomics/T1082/src/FILE.txt"],
        ["atomics/T1082/src", "atomics/T1082/src/file.txt"],
    ],
)
def test_duplicate_case_and_prefix_collisions_reject_submission(env, paths):
    result = submit(env, files=[{"path": path, "content_base64": "Zml4dHVyZQ=="} for path in paths])
    assert result.status_code == 422
