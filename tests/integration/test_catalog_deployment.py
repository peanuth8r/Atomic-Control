import copy
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.agent.catalog_config import verify_manifest
from apps.agent.job_client import heartbeat_payload
from apps.agent.linux import catalog_sync as installer
from apps.agent.linux import security
from apps.api.app.auth import Principal, human
from apps.api.app.catalog.parser import parse_file
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import (
    Actor,
    AtomicTest,
    Attempt,
    Audit,
    Base,
    CatalogDeployment,
    Credential,
    Lease,
    Profile,
    ProfileSync,
    Revision,
    Run,
)
from apps.api.app.services.common import digest, fingerprint


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    guid = str(uuid4())
    atomic = {
        "attack_technique": "T1082",
        "display_name": "Synthetic catalog fixture",
        "atomic_tests": [
            {
                "auto_generated_guid": guid,
                "name": "Synthetic fixture",
                "description": "No test is executed",
                "supported_platforms": ["linux"],
                "executor": {"name": "bash", "command": "printf synthetic"},
                "input_arguments": {},
            }
        ],
    }
    file = source / "atomics/T1082/T1082.yaml"
    file.parent.mkdir(parents=True)
    file.write_text(yaml.safe_dump(atomic))
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    for args in [
        ("init", "--quiet"),
        ("add", "."),
        (
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ),
    ]:
        subprocess.run(["/usr/bin/git", "-C", str(source), *args], env=env, check=True, capture_output=True)
    revision = subprocess.check_output(
        ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    definition = parse_file(file)[0]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    signing = tmp_path / "signing.pem"
    signing.write_bytes(private)
    app = create_app(
        Settings(
            mode="real",
            database_url=f"sqlite:///{tmp_path}/catalog.db",
            signing_key_file=str(signing),
            oidc_issuer="https://id.example.test",
            oidc_jwks_url="https://id.example.test/certs",
        )
    )
    Base.metadata.create_all(app.state.engine)
    app.dependency_overrides[human] = lambda: Principal(
        "human-admin", frozenset({"viewer", "administrator", "operator"}), frozenset()
    )
    actor_id = str(uuid4())
    with app.state.sessions() as db, db.begin():
        db.add(
            Actor(
                id=actor_id,
                hostname="catalog-fixture",
                os="linux",
                catalog_sync_protocol=1,
                health="healthy",
                last_heartbeat=time.time(),
            )
        )
        db.add(Revision(id=revision))
        db.flush()
        db.add(
            AtomicTest(
                guid=guid,
                technique="T1082",
                name="Synthetic fixture",
                revision=revision,
                content_hash=fingerprint(definition),
                definition=definition,
            )
        )
        db.add(
            Credential(actor_id=actor_id, digest=digest("agent-test-secret"), expires_at=time.time() + 3600)
        )
    root = tmp_path / "agent"
    root.mkdir()
    (root / "atomic-red-team").mkdir()
    (root / "atomic-red-team/previous.txt").write_text("preserve previous checkout")
    (root / "job-signing-public.pem").write_text(public)
    state = tmp_path / "state/jobs"
    state.mkdir(parents=True)
    credentials = tmp_path / "credential.json"
    credentials.write_text("preserved transport credentials")
    config = {
        "actor_id": actor_id,
        "hostname": "catalog-fixture",
        "os": "linux",
        "os_version": "Linux",
        "profiles": [],
        "api_url": "https://control.example.test",
        "revision": "",
        "catalog_root": str(root / "atomic-red-team"),
        "public_key_file": str(root / "job-signing-public.pem"),
        "credential_file": str(credentials),
        "state_root": str(state),
        "catalog_sync_enabled": True,
        "profile_sync_enabled": False,
    }
    config_file = tmp_path / "agent.json"
    config_file.write_text(json.dumps(config))
    monkeypatch.setattr(installer, "protected", lambda *args, **kwargs: None)
    monkeypatch.setattr(installer, "protected_tree", lambda *args: None)
    monkeypatch.setattr(security, "protected", lambda *args, **kwargs: None)
    fetches = []

    def fetch(target, commit):
        assert commit == revision
        fetches.append(commit)
        shutil.copytree(source, target)

    monkeypatch.setattr(installer, "fetch", fetch)
    return {
        "app": app,
        "client": TestClient(app),
        "actor": actor_id,
        "agent": {"Authorization": "Bearer agent-test-secret"},
        "revision": revision,
        "guid": guid,
        "config": config,
        "file": config_file,
        "source": source,
        "private": private,
        "public": public,
        "fetches": fetches,
    }


def request_install(s):
    response = s["client"].get(f"/api/v1/actors/{s['actor']}/catalog-options")
    assert response.status_code == 200, response.text
    option = response.json()["revisions"][0]
    response = s["client"].post(
        f"/api/v1/actors/{s['actor']}/catalog-install",
        json={"revision": option["revision"], "manifest_hash": option["manifest_hash"], "confirmed": True},
    )
    assert response.status_code == 200, response.text
    return response


def poll(s):
    response = s["client"].post("/api/v1/agents/catalog-install/poll", headers=s["agent"])
    assert response.status_code == 200, response.text
    return response.json()


def ack(s, saved):
    return s["client"].post(
        f"/api/v1/agents/catalog-install/{saved['id']}/result", headers=s["agent"], json=saved["result"]
    )


def test_signed_installation_verifies_real_git_and_yaml_before_reporting_a_pin(catalog):
    s = catalog
    before = Path(s["config"]["credential_file"]).read_bytes()
    request_install(s)
    token = poll(s)["manifest"]
    assert s["client"].post("/api/v1/agents/jobs/claim", headers=s["agent"]).json() == {"job": None}
    config, saved = installer.apply_manifest(s["config"], s["file"], token)
    assert saved["result"]["status"] == "applied" and config["revision"] == s["revision"]
    assert ack(s, saved).json()["status"] == "applied"
    assert ack(s, saved).status_code == 200
    response = s["client"].post(
        "/api/v1/agents/heartbeat", headers=s["agent"], json=heartbeat_payload(config)
    )
    assert response.status_code == 200, response.text
    actor = s["client"].get(f"/api/v1/actors/{s['actor']}").json()
    assert actor["revision"] == s["revision"] and actor["catalog"]["health"] == "ready"
    assert list(Path(config["catalog_root"]).parent.glob("catalog-before-*/previous.txt"))
    assert Path(config["credential_file"]).read_bytes() == before and s["fetches"] == [s["revision"]]
    assert not installer.journal_path(config).exists()
    # A repeated grant after lost ACK verifies the receipt without fetching/installing again.
    again, saved2 = installer.apply_manifest(config, s["file"], token)
    assert again == config and saved2 == saved and len(s["fetches"]) == 1
    with s["app"].state.sessions() as db:
        assert db.scalar(select(Run)) is None


def test_ui_cannot_fake_pin_and_dirty_checkout_stops_advertising_revision(catalog):
    s = catalog
    data = heartbeat_payload(s["config"])
    data.update(revision=s["revision"], catalog_health="ready", catalog_config_hash="a" * 64)
    assert s["client"].post("/api/v1/agents/heartbeat", headers=s["agent"], json=data).status_code == 200
    assert s["client"].get(f"/api/v1/actors/{s['actor']}").json()["revision"] == ""
    request_install(s)
    config, saved = installer.apply_manifest(s["config"], s["file"], poll(s)["manifest"])
    ack(s, saved)
    (Path(config["catalog_root"]) / "unexpected.txt").write_text("unreviewed change")
    assert installer.readiness(config) == ("dirty", "", "")
    data = heartbeat_payload(config)
    s["client"].post("/api/v1/agents/heartbeat", headers=s["agent"], json=data)
    assert s["client"].get(f"/api/v1/actors/{s['actor']}").json()["revision"] == ""


@pytest.mark.parametrize(
    "change", ["issuer", "audience", "source", "revision", "url", "hash", "replay", "key"]
)
def test_agent_rejects_untrusted_commands_sources_and_replay(catalog, change):
    s = catalog
    request_install(s)
    token = poll(s)["manifest"]
    claims = jwt.decode(token, options={"verify_signature": False})
    config = copy.deepcopy(s["config"])
    key = s["private"]
    if change == "issuer":
        claims["iss"] = "atomic-control"
    elif change == "audience":
        claims["aud"] = str(uuid4())
    elif change == "source":
        claims["payload"]["source"] = "attacker/repository"
    elif change == "revision":
        claims["payload"]["revision"] = "master"
    elif change == "url":
        claims["payload"]["url"] = "https://attacker.example.test"
    elif change == "hash":
        claims["payload_hash"] = "0" * 64
    elif change == "replay":
        config["catalog_sync_generation"] = 100
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises((ValueError, jwt.PyJWTError)):
        installer.apply_manifest(config, s["file"], jwt.encode(claims, key, algorithm="RS256"))
    assert not s["fetches"] and Path(config["catalog_root"], "previous.txt").exists()


@pytest.mark.parametrize("failure", ["fetch", "verification", "disk"])
def test_failed_install_preserves_previous_catalog_and_configuration(catalog, monkeypatch, failure):
    s = catalog
    request_install(s)
    token = poll(s)["manifest"]
    if failure == "fetch":
        monkeypatch.setattr(
            installer, "fetch", lambda *a: (_ for _ in ()).throw(installer.CatalogFailure("fetch_failed"))
        )
    elif failure == "verification":

        def bad_fetch(target, revision):
            shutil.copytree(s["source"], target)
            (target / "atomics/T1082/T1082.yaml").write_text("tampered")

        monkeypatch.setattr(installer, "fetch", bad_fetch)
    else:
        monkeypatch.setattr(installer.shutil, "disk_usage", lambda *_: SimpleNamespace(free=0))
    config, saved = installer.apply_manifest(s["config"], s["file"], token)
    assert saved["result"]["status"] == "failed" and config["revision"] == ""
    assert (Path(config["catalog_root"]) / "previous.txt").read_text() == "preserve previous checkout"
    assert ack(s, saved).json()["status"] == "failed"
    assert not installer.journal_path(config).exists()
    for field in ("api_url", "credential_file", "public_key_file", "profiles"):
        assert config[field] == s["config"][field]


@pytest.mark.parametrize("phase", ["fetch", "switch", "receipt", "complete"])
def test_crash_recovery_restores_prior_catalog_or_finishes_a_durable_receipt(catalog, monkeypatch, phase):
    s = catalog
    request_install(s)
    token = poll(s)["manifest"]
    original_fetch, original_rename = installer.fetch, Path.rename
    original_receipt, original_clear = installer.receipt, installer.clear_journal
    if phase == "fetch":

        def crash_fetch(target, revision):
            target.mkdir()
            (target / "partial").write_text("partial download")
            raise KeyboardInterrupt()

        monkeypatch.setattr(installer, "fetch", crash_fetch)
    elif phase == "switch":

        def rename(path, target):
            if path.name.startswith(".catalog-stage-"):
                raise KeyboardInterrupt()
            return original_rename(path, target)

        monkeypatch.setattr(Path, "rename", rename)
    elif phase == "receipt":
        monkeypatch.setattr(installer, "receipt", lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    else:
        monkeypatch.setattr(installer, "clear_journal", lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        installer.apply_manifest(s["config"], s["file"], token)
    assert installer.journal_path(s["config"]).exists()
    monkeypatch.setattr(installer, "fetch", original_fetch)
    monkeypatch.setattr(Path, "rename", original_rename)
    monkeypatch.setattr(installer, "receipt", original_receipt)
    monkeypatch.setattr(installer, "clear_journal", original_clear)
    recovered = installer.recover(s["file"])
    assert not installer.journal_path(recovered).exists()
    saved = recovered["catalog_sync_receipt"]
    if phase == "complete":
        assert saved["result"]["status"] == "applied" and recovered["revision"] == s["revision"]
    else:
        assert saved["result"]["status"] == "failed" and saved["result"]["error"] == "interrupted"
        assert (Path(recovered["catalog_root"]) / "previous.txt").read_text() == "preserve previous checkout"
    assert ack(s, saved).status_code == 200


def test_wrong_actor_roles_and_stale_confirmation_are_rejected(catalog):
    s = catalog
    option = s["client"].get(f"/api/v1/actors/{s['actor']}/catalog-options").json()["revisions"][0]
    body = {"revision": option["revision"], "manifest_hash": "0" * 64, "confirmed": True}
    assert s["client"].post(f"/api/v1/actors/{s['actor']}/catalog-install", json=body).status_code == 409
    body["manifest_hash"] = option["manifest_hash"]
    body["confirmed"] = False
    assert s["client"].post(f"/api/v1/actors/{s['actor']}/catalog-install", json=body).status_code == 422
    for principal in [
        Principal("operator", frozenset({"viewer", "operator"}), frozenset()),
        Principal("mcp", frozenset({"administrator", "viewer"}), frozenset(), True),
    ]:
        s["app"].dependency_overrides[human] = lambda principal=principal: principal
        assert (
            s["client"]
            .post(f"/api/v1/actors/{s['actor']}/catalog-install", json={**body, "confirmed": True})
            .status_code
            == 403
        )
    assert s["client"].post("/api/v1/agents/catalog-install/poll").status_code == 401


def test_active_lease_and_profile_sync_defer_catalog_dispatch(catalog):
    s = catalog
    request_install(s)
    with s["app"].state.sessions() as db, db.begin():
        db.add(
            ProfileSync(
                actor_id=s["actor"],
                generation=1,
                payload={},
                payload_hash="a" * 64,
                requested_by="admin",
                status="pending",
            )
        )
    assert poll(s) == {"manifest": None, "waiting_for_idle": True}
    with s["app"].state.sessions() as db, db.begin():
        db.scalar(select(ProfileSync)).status = "applied"
        profile = Profile(
            actor_id=s["actor"],
            profile_key="standard-user",
            display_name="Fixture",
            account="fixture",
            expected_sid="uid:1000",
            privilege="standard",
            logon_type="systemd",
        )
        db.add(profile)
        db.flush()
        run = Run(
            actor_id=s["actor"],
            profile_id=profile.id,
            guid=s["guid"],
            requested_by="fixture",
            idempotency_key="uncertain-catalog-fixture",
            request_hash="a" * 64,
            reason="Synthetic uncertain lease",
            action="execute",
            status="inconclusive",
            snapshot={},
            snapshot_hash="a" * 64,
        )
        db.add(run)
        db.flush()
        attempt = Attempt(run_id=run.id)
        db.add(attempt)
        db.flush()
        db.add(Lease(actor_id=s["actor"], run_id=run.id, attempt_id=attempt.id, fence="a" * 64, expires_at=0))
    assert poll(s) == {"manifest": None, "waiting_for_idle": True}


def test_catalog_apply_blocks_profile_dispatch_and_retirement(catalog):
    s = catalog
    request_install(s)
    poll(s)
    with s["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, s["actor"])
        actor.profile_sync_protocol = 1
        db.add(
            ProfileSync(
                actor_id=s["actor"],
                generation=1,
                payload={},
                payload_hash="a" * 64,
                requested_by="admin",
                status="pending",
            )
        )
    assert s["client"].post("/api/v1/agents/profile-sync/poll", headers=s["agent"]).json()["waiting_for_idle"]
    assert (
        s["client"]
        .post(
            f"/api/v1/actors/{s['actor']}/retire",
            json={"hostname": "catalog-fixture", "reason": "Retire synthetic fixture"},
        )
        .status_code
        == 409
    )


def test_git_fetch_uses_only_fixed_https_remote_and_disables_hooks_and_credential_helpers(
    catalog, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        subprocess, "run", lambda command, **kw: calls.append((command, kw)) or SimpleNamespace(stdout="")
    )
    installer.git(
        Path(catalog["config"]["catalog_root"]),
        "fetch",
        "--depth=1",
        "https://github.com/redcanaryco/atomic-red-team.git",
        catalog["revision"],
    )
    command, kwargs = calls[0]
    assert "core.hooksPath=/dev/null" in command and "credential.helper=" in command
    assert kwargs["env"]["GIT_ALLOW_PROTOCOL"] == "https" and "Authorization" not in str(command)


def test_upgrade_is_required_and_retired_actors_cannot_install(catalog):
    s = catalog
    option = s["client"].get(f"/api/v1/actors/{s['actor']}/catalog-options").json()["revisions"][0]
    body = {"revision": option["revision"], "manifest_hash": option["manifest_hash"], "confirmed": True}
    with s["app"].state.sessions() as db, db.begin():
        db.get(Actor, s["actor"]).catalog_sync_protocol = 0
    assert (
        s["client"].post(f"/api/v1/actors/{s['actor']}/catalog-install", json=body).json()["error"]["code"]
        == "agent_upgrade_required"
    )
    with s["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, s["actor"])
        actor.registration_state = "retired"
    assert (
        s["client"].post(f"/api/v1/actors/{s['actor']}/catalog-install", json=body).json()["error"]["code"]
        == "actor_retired"
    )


def test_pending_catalog_install_is_cancelled_by_retirement(catalog):
    s = catalog
    request_install(s)
    response = s["client"].post(
        f"/api/v1/actors/{s['actor']}/retire",
        json={"hostname": "catalog-fixture", "reason": "Synthetic decommissioning verification"},
    )
    assert response.status_code == 200, response.text
    with s["app"].state.sessions() as db:
        assert db.scalar(select(CatalogDeployment)) is None
        assert (
            db.scalar(select(Audit).where(Audit.action == "actor.deleted")).details[
                "catalog_deployments_cancelled"
            ]
            == 1
        )
        assert db.get(Actor, s["actor"]) is None
        assert db.scalar(select(Run)) is None


def test_wrong_actor_or_revision_cannot_acknowledge_an_installation(catalog):
    s = catalog
    request_install(s)
    claims = verify_manifest(poll(s)["manifest"], s["config"], s["public"])
    result = {
        "generation": claims["generation"],
        "payload_hash": claims["payload_hash"],
        "status": "applied",
        "observed_revision": "0" * 40,
        "error": "",
    }
    path = f"/api/v1/agents/catalog-install/{claims['jti']}/result"
    assert s["client"].post(path, headers=s["agent"], json=result).status_code == 422
    other = str(uuid4())
    with s["app"].state.sessions() as db, db.begin():
        db.add(Actor(id=other, hostname="another-agent", os="linux"))
        db.flush()
        db.add(Credential(actor_id=other, digest=digest("other-secret"), expires_at=time.time() + 3600))
    result["observed_revision"] = s["revision"]
    assert (
        s["client"].post(path, headers={"Authorization": "Bearer other-secret"}, json=result).status_code
        == 404
    )
    result["generation"] += 1
    assert s["client"].post(path, headers=s["agent"], json=result).status_code == 409


def test_new_catalog_receipt_does_not_bring_back_a_dirty_pin(catalog):
    s = catalog
    request_install(s)
    config, saved = installer.apply_manifest(s["config"], s["file"], poll(s)["manifest"])
    assert ack(s, saved).status_code == 200
    (Path(config["catalog_root"]) / "untracked.txt").write_text("changed")
    s["client"].post("/api/v1/agents/heartbeat", headers=s["agent"], json=heartbeat_payload(config))
    assert ack(s, saved).status_code == 200
    assert s["client"].get(f"/api/v1/actors/{s['actor']}").json()["revision"] == ""


def test_normalization_preserves_executable_mode_and_makes_checkout_readable(tmp_path, monkeypatch):
    root = tmp_path / "stage"
    root.mkdir(mode=0o700)
    plain = root / "plain"
    plain.write_text("data")
    plain.chmod(0o600)
    executable = root / "script"
    executable.write_text("fixture text")
    executable.chmod(0o700)
    owners = []
    monkeypatch.setattr(installer.os, "chown", lambda path, uid, gid, **kwargs: owners.append((uid, gid)))
    installer.normalize_tree(root)
    assert root.stat().st_mode & 0o777 == 0o755
    assert plain.stat().st_mode & 0o777 == 0o644
    assert executable.stat().st_mode & 0o777 == 0o755
    assert owners and set(owners) == {(0, 0)}


def test_normalization_refuses_links_without_touching_their_targets(tmp_path, monkeypatch):
    root = tmp_path / "stage"
    root.mkdir()
    target = tmp_path / "outside"
    target.write_text("preserve")
    target.chmod(0o600)
    (root / "link").symlink_to(target)
    monkeypatch.setattr(installer.os, "chown", lambda *args, **kwargs: None)
    with pytest.raises(installer.CatalogFailure):
        installer.normalize_tree(root)
    assert target.read_text() == "preserve" and target.stat().st_mode & 0o777 == 0o600
