from pathlib import Path

import pytest

from apps.agent.identity_validation import IdentityMismatch, validate_identity
from apps.api.app.catalog.parser import import_catalog, parse_file
from apps.api.app.models import TestApproval as Approval


def test_catalog_parses_guid_commands_and_arguments():
    definition = parse_file(Path("tests/fixtures/catalog/T1082/T1082.yaml"))[0]
    assert definition["technique"] == "T1082"
    assert definition["executor"]["cleanup_command"]
    assert definition["auto_generated_guid"] == "11111111-1111-4111-8111-111111111111"


def test_reimport_changed_definition_invalidates_approval(env, tmp_path, monkeypatch):
    fixture = tmp_path / "T1082.yaml"
    fixture.write_text(
        Path("tests/fixtures/catalog/T1082/T1082.yaml").read_text().replace("TEST FIXTURE", "CHANGED")
    )
    with env["app"].state.sessions() as db, db.begin():
        monkeypatch.setattr(
            "apps.api.app.catalog.parser.subprocess.check_output",
            lambda command, **kw: "c" * 40 if "rev-parse" in command else "",
        )
        import_catalog(db, tmp_path, "c" * 40)
        assert not db.get(Approval, "11111111-1111-4111-8111-111111111111").approved


@pytest.mark.parametrize(
    "field,value",
    [
        ("actual_account_sid", "S-1-5-18"),
        ("elevated", True),
        ("admin_member", True),
        ("integrity_level", "high"),
    ],
)
def test_standard_user_identity_cannot_escalate(field, value):
    identity = {
        "actual_account_sid": "S-1-5-21-1",
        "elevated": False,
        "admin_member": False,
        "integrity_level": "medium",
    }
    identity[field] = value
    with pytest.raises(IdentityMismatch):
        validate_identity(identity, {"expected_sid": "S-1-5-21-1", "privilege": "standard"})


def test_admin_membership_without_elevation_rejected():
    with pytest.raises(IdentityMismatch):
        validate_identity(
            {
                "actual_account_sid": "S-1-5-21-1",
                "elevated": False,
                "admin_member": True,
                "integrity_level": "medium",
            },
            {"expected_sid": "S-1-5-21-1", "privilege": "elevated"},
        )


def test_real_job_grant_signature_actor_and_expiry(monkeypatch):
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from apps.agent.execution_broker import verify_job
    from apps.api.app.services.common import fingerprint

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    uid = "11111111-1111-4111-8111-111111111111"
    profile = {
        "id": uid,
        "enabled": True,
        "validated": True,
        "expected_sid": "S-1-5-21-1",
        "privilege": "standard",
        "profile_key": "standard-user",
    }
    snapshot = {
        "simulated": False,
        "actor_id": uid,
        "execution_profile_id": uid,
        "action": "execute",
        "timeout_seconds": 120,
        "definition": {"supported_platforms": ["windows"], "executor": {"name": "powershell"}},
        "expected_sid": profile["expected_sid"],
        "privilege": "standard",
        "profile_key": "standard-user",
    }
    job = {
        "run_id": uid,
        "attempt_id": uid,
        "fence": "a" * 64,
        "snapshot": snapshot,
        "snapshot_hash": fingerprint(snapshot),
        "lease_expires_at": time.time() + 60,
    }
    config = {"actor_id": uid, "profiles": [profile], "catalog_root": "unused", "revision": "pinned"}
    monkeypatch.setattr("apps.agent.execution_broker.validate_catalog", lambda *_: None)
    claims = {
        **job,
        "iss": "atomic-control",
        "aud": uid,
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
    }
    job["grant"] = jwt.encode(claims, private, algorithm="RS256")
    assert verify_job(job, config, public)["id"] == uid
    with pytest.raises(ValueError):
        verify_job({**job, "fence": "b" * 64}, config, public)
    with pytest.raises(jwt.InvalidAudienceError):
        verify_job(job, {**config, "actor_id": "other-actor"}, public)
    expired = {
        **job,
        "grant": jwt.encode({**claims, "exp": int(time.time()) - 1}, private, algorithm="RS256"),
    }
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_job(expired, config, public)


def test_task_identity_mismatch_reports_failure_before_process(monkeypatch, tmp_path):
    import json

    from apps.agent.task_wrapper import run

    uid = "11111111-1111-4111-8111-111111111111"
    folder = tmp_path / uid
    (folder / "output").mkdir(parents=True)
    config = {"state_root": str(tmp_path), "public_key_file": str(tmp_path / "public.pem")}
    (tmp_path / "public.pem").write_text("not-used")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    (folder / "job.json").write_text(json.dumps({"attempt_id": uid}))
    (folder / "lease.json").write_text(
        json.dumps({"attempt_id": uid, "expires_at": __import__("time").time() + 60})
    )
    profile = {"id": uid, "expected_sid": "S-1-5-21-1", "privilege": "standard"}
    monkeypatch.setattr("apps.agent.task_wrapper.verify_job", lambda *_: profile)
    monkeypatch.setattr(
        "apps.agent.task_wrapper.capture_identity",
        lambda *_: {"actual_account_sid": "S-1-5-18", "verified": False},
    )

    def forbidden(*_, **__):
        raise AssertionError("PowerShell must not start after identity mismatch")

    monkeypatch.setattr("apps.agent.task_wrapper.subprocess.Popen", forbidden)
    run(config_file, uid)
    evidence = json.loads((folder / "output" / "result.json").read_text())
    assert evidence["status"] == "failed"
    assert evidence["identity"]["actual_account_sid"] == "S-1-5-18"
