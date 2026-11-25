"""Existing definition approvals carry their exact inline YAML into on-demand runs."""

from uuid import uuid4

import pytest
from sqlalchemy import func, select

from apps.api.app.jobs import preparation
from apps.api.app.models import Actor, AtomicTest, Audit, FilePlan, Lease, SourceBlob
from apps.api.app.models import TestApproval as Approval
from apps.api.app.services.common import fingerprint

GUID = "11111111-1111-4111-8111-111111111111"
OP = {"X-Test-User": "operator"}


@pytest.fixture
def legacy(env, monkeypatch):
    env["settings"].approval_mode = "catalog"
    env["settings"].policy_file = ""
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.delivery_mode, actor.artifact_protocol, actor.revision = "on_demand", 1, ""
        review = db.get(Approval, GUID)
        env["approval_before"] = {
            k: getattr(review, k)
            for k in (
                "content_hash",
                "revision",
                "allowed_profiles",
                "allowed_platforms",
                "risk_level",
                "approved_by",
                "approved",
            )
        }

    def no_network(*args, **kwargs):
        raise AssertionError("Inline delivery must not fetch source files")

    monkeypatch.setattr("apps.api.app.services.file_plans.fetch_assets", no_network)
    return env


def request(env, key=None):
    return env["client"].post(
        "/api/v1/runs",
        headers={**OP, "Idempotency-Key": key or str(uuid4())},
        json={
            "atomic_guid": GUID,
            "actor_id": env["actor"],
            "execution_profile_id": env["profiles"][0]["id"],
            "reason": "Authorized isolated inline delivery verification",
        },
    )


def test_standing_approval_prepares_inline_test_without_reapproval(legacy):
    response = request(legacy, "inline-once")
    assert response.status_code == 201, response.text
    run = response.json()
    key = run["snapshot"]["file_plan"]["hash"]
    with legacy["app"].state.sessions() as db:
        review = db.get(Approval, GUID)
        assert {k: getattr(review, k) for k in legacy["approval_before"]} == legacy["approval_before"]
        plan = db.get(FilePlan, key)
        assert plan.approval["approved_by"] == review.approved_by
        assert [f["path"] for f in plan.manifest["files"]] == ["atomics/T1082/T1082.yaml"]
        assert db.scalar(select(func.count()).select_from(Audit).where(Audit.action == "catalog.review")) == 0
    assert request(legacy, "inline-once").json()["run_id"] == run["run_id"]
    claim = legacy["client"].post("/api/v1/agents/jobs/claim", headers=legacy["agent"], json={})
    assert claim.json()["job"] is None
    with legacy["app"].state.sessions() as db:
        assert db.get(Lease, legacy["actor"]) is None
    assert preparation.process_once(legacy["app"].state.sessions, legacy["settings"])
    job = legacy["client"].post("/api/v1/agents/jobs/claim", headers=legacy["agent"], json={}).json()["job"]
    assert job["snapshot"]["artifact"]["manifest"]["guid"] == GUID
    with legacy["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(FilePlan)) == 1
        assert (
            db.scalar(
                select(func.count())
                .select_from(Audit)
                .where(Audit.action == "file-plan.inherited-catalog-approval")
            )
            == 1
        )


def test_batch_preview_and_submission_need_no_second_approval(legacy):
    path = f"/api/v1/actors/{legacy['actor']}/queue"
    payload = {"execution_profile_id": legacy["profiles"][0]["id"], "atomic_guids": [GUID]}
    preview = legacy["client"].post(path + "/preview", headers=OP, json=payload)
    assert preview.status_code == 200, preview.text
    assert preview.json()["eligible_count"] == 1
    response = legacy["client"].post(
        path,
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={
            **payload,
            "preview_hash": preview.json()["preview_hash"],
            "reason": "Authorized inline batch validation",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["total"] == 1


@pytest.mark.parametrize("mutation", ["revoked", "changed", "external_files"])
def test_invalid_or_incomplete_approvals_are_not_extended(legacy, mutation):
    with legacy["app"].state.sessions() as db, db.begin():
        test, review = db.get(AtomicTest, GUID), db.get(Approval, GUID)
        if mutation == "revoked":
            review.approved = False
        else:
            test.definition = {
                **test.definition,
                "input_arguments": {"path": {"default": "#{PathToAtomicsFolder}/T1082/src/example.ps1"}},
            }
            test.content_hash = fingerprint(test.definition)
            if mutation == "external_files":
                review.content_hash = test.content_hash
    response = request(legacy)
    assert response.status_code == 409, response.text
    with legacy["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(FilePlan)) == 0


def test_corrupt_retained_inline_blob_is_not_silently_repaired(legacy):
    assert request(legacy).status_code == 201
    with legacy["app"].state.sessions() as db, db.begin():
        db.get(Approval, GUID).plan_hash = ""
        db.scalar(select(SourceBlob)).content = b"changed outside the approved definition"
    response = request(legacy)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "file_plan_invalid"
