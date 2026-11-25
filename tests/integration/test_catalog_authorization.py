from uuid import uuid4

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Request
from sqlalchemy import func, select

from apps.api.app.auth import Principal, human
from apps.api.app.models import Actor, AtomicTest, Audit, Lease, Profile, Revision, Run, RunApproval
from apps.api.app.models import TestApproval as CatalogApproval
from apps.api.app.services.common import fingerprint

GUID = "11111111-1111-4111-8111-111111111111"
REVISION = "a" * 40


@pytest.fixture
def catalog(env, tmp_path):
    settings = env["settings"]
    settings.mode, settings.dev_auth, settings.approval_mode = "real", False, "catalog"
    settings.policy_file = ""
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private = tmp_path / "signing.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    settings.signing_key_file = str(private)

    def identity(request: Request):
        user = request.headers.get("x-test-user", "operator")
        roles = {
            "operator": {"viewer", "operator"},
            "viewer": {"viewer"},
            "admin": {"viewer", "operator", "administrator", "approver", "privileged_approver"},
            "approver": {"viewer", "approver", "privileged_approver"},
        }[user]
        return Principal(
            "human:" + user,
            frozenset(roles),
            frozenset(request.headers.get("x-test-scope", "").split()),
            request.headers.get("x-test-mcp") == "true",
        )

    env["app"].dependency_overrides[human] = identity
    with env["app"].state.sessions() as db, db.begin():
        db.add(Revision(id=REVISION))
        db.flush()
        actor = db.get(Actor, env["actor"])
        actor.os, actor.os_version, actor.simulated, actor.revision = (
            "linux",
            "Linux fixture",
            False,
            REVISION,
        )
        test = db.get(AtomicTest, GUID)
        test.definition = {
            **test.definition,
            "supported_platforms": ["linux"],
            "executor": {
                "name": "bash",
                "command": "printf 'not executed'",
                "cleanup_command": "printf 'not executed'",
            },
        }
        test.content_hash = fingerprint(test.definition)
        test.simulated, test.revision = False, REVISION
        review = db.get(CatalogApproval, GUID)
        review.revision, review.content_hash, review.allowed_platforms, review.approved_by = (
            REVISION,
            test.content_hash,
            ["linux"],
            "human:catalog-admin",
        )
        for profile in db.scalars(select(Profile).where(Profile.actor_id == actor.id)):
            profile.account, profile.expected_sid = (
                ("root", "uid:0") if profile.privilege == "elevated" else ("atomic-user", "uid:1001")
            )
            profile.logon_type = "systemd"
    return {**env, "public_key": key.public_key()}


def request(catalog, profile="standard-user", user="operator", key=None, **headers):
    return catalog["client"].post(
        "/api/v1/runs",
        headers={"X-Test-User": user, "Idempotency-Key": key or str(uuid4()), **headers},
        json={
            "atomic_guid": GUID,
            "actor_id": catalog["actor"],
            "execution_profile_id": next(p["id"] for p in catalog["profiles"] if p["profile_key"] == profile),
            "reason": "Explicit approved fixture request",
        },
    )


@pytest.mark.parametrize("profile", ["standard-user", "local-admin"])
def test_catalog_review_authorizes_direct_queue_and_signed_claim_without_subject_grants(catalog, profile):
    response = request(catalog, profile)
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["status"] == "queued" and run["approval_required"] is False
    assert run["authorization_source"] == "catalog" and run["approved_by"] == "human:catalog-admin"
    assert run["requested_by"] == "human:operator"
    assert catalog["client"].get("/api/v1/approvals").json()["items"] == []
    job = catalog["client"].post("/api/v1/agents/jobs/claim", headers=catalog["agent"], json={}).json()["job"]
    assert job and job["run_id"] == run["run_id"]
    signed = jwt.decode(
        job["grant"],
        catalog["public_key"],
        algorithms=["RS256"],
        audience=catalog["actor"],
        issuer="atomic-control",
    )
    assert signed["snapshot"] == job["snapshot"] and signed["snapshot_hash"] == fingerprint(job["snapshot"])
    assert signed["snapshot"]["actor_os"] == "linux" and signed["snapshot"]["profile_key"] == profile
    with catalog["app"].state.sessions() as db:
        actions = set(db.scalars(select(Audit.action)))
        assert "run.catalog_authorized" in actions and "run.approve" not in actions


@pytest.mark.parametrize(
    "change",
    [
        "disabled",
        "offline",
        "profile",
        "revision",
        "unapproved",
        "unsupported",
        "unregistered",
        "wrong_profile_approval",
    ],
)
def test_catalog_approval_never_bypasses_host_identity_and_definition_eligibility(catalog, change):
    with catalog["app"].state.sessions() as db, db.begin():
        actor, test = db.get(Actor, catalog["actor"]), db.get(AtomicTest, GUID)
        if change == "disabled":
            actor.enabled = False
        elif change == "offline":
            actor.last_heartbeat = 0
        elif change == "profile":
            db.get(Profile, catalog["profiles"][0]["id"]).healthy = False
        elif change == "revision":
            actor.revision = "b" * 40
        elif change == "unapproved":
            db.get(CatalogApproval, GUID).approved = False
        elif change == "unregistered":
            db.delete(
                db.get(
                    Profile, next(p["id"] for p in catalog["profiles"] if p["profile_key"] == "standard-user")
                )
            )
        elif change == "wrong_profile_approval":
            db.get(CatalogApproval, GUID).allowed_profiles = ["local-admin"]
        else:
            test.definition = {**test.definition, "executor": {"name": "manual", "steps": "unsupported"}}
            test.content_hash = fingerprint(test.definition)
            db.get(CatalogApproval, GUID).content_hash = test.content_hash
    response = request(catalog)
    assert response.status_code in {403, 409}, response.text
    with catalog["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Run)) == 0


def test_catalog_mode_still_requires_operator_role_and_mcp_action_scope(catalog):
    assert request(catalog, user="viewer").status_code == 403
    assert request(catalog, **{"x-test-mcp": "true", "x-test-scope": "atomic:read"}).status_code == 403
    assert (
        request(catalog, **{"x-test-mcp": "true", "x-test-scope": "atomic:read atomic:request"}).json()[
            "status"
        ]
        == "queued"
    )


def test_revoking_catalog_approval_blocks_queued_work_at_claim(catalog):
    run = request(catalog).json()
    with catalog["app"].state.sessions() as db, db.begin():
        db.get(CatalogApproval, GUID).approved = False
    response = catalog["client"].post("/api/v1/agents/jobs/claim", headers=catalog["agent"], json={})
    assert response.status_code == 409
    with catalog["app"].state.sessions() as db:
        assert db.get(Lease, catalog["actor"]) is None
        assert db.get(Run, run["run_id"]).status != "claimed"


def test_catalog_request_retries_are_idempotent_and_cleanup_is_queued_separately(catalog):
    first = request(catalog, key="one-request").json()
    second = request(catalog, key="one-request").json()
    assert first["run_id"] == second["run_id"]
    with catalog["app"].state.sessions() as db, db.begin():
        assert db.scalar(select(func.count()).select_from(RunApproval)) == 1
        db.get(Run, first["run_id"]).status = "succeeded"
    cleanup = catalog["client"].post(
        f"/api/v1/runs/{first['run_id']}/cleanup",
        headers={"Idempotency-Key": str(uuid4())},
        json={"reason": "Explicit separate fixture cleanup"},
    )
    assert cleanup.status_code == 201, cleanup.text
    assert cleanup.json()["status"] == "queued" and cleanup.json()["authorization_source"] == "catalog"
    assert cleanup.json()["parent_id"] == first["run_id"]


def test_optional_per_run_mode_keeps_scope_policy_and_manual_approval(catalog, tmp_path):
    catalog["settings"].approval_mode = "per_run"
    assert request(catalog).status_code == 403
    profile = next(p for p in catalog["profiles"] if p["profile_key"] == "standard-user")
    path = tmp_path / "scopes.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "subjects": {
                    "human:operator": [
                        {
                            "actions": ["execute"],
                            "actors": [catalog["actor"]],
                            "profiles": [profile["id"]],
                            "tests": [GUID],
                            "risks": ["low"],
                        }
                    ]
                }
            }
        )
    )
    catalog["settings"].policy_file = str(path)
    response = request(catalog)
    assert response.status_code == 201 and response.json()["status"] == "pending_approval"
    assert (
        catalog["client"].post("/api/v1/agents/jobs/claim", headers=catalog["agent"], json={}).json()["job"]
        is None
    )


def test_catalog_mode_disables_unneeded_subject_grant_editor(catalog):
    response = catalog["client"].get("/api/v1/execution-access", headers={"X-Test-User": "admin"})
    assert response.status_code == 200 and response.json()["configured"] is False
    assert "No separate" in response.json()["message"]
