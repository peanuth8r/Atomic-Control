import copy
import json
import time
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.agent.linux import profile_sync as agent_sync
from apps.agent.profile_config import fingerprint, payload, verify_manifest
from apps.api.app.auth import Principal, human
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import Actor, Base, Credential, Lease, Profile, ProfileSync, Run
from apps.api.app.services.common import digest


def evidence(profile):
    uid = int(profile["expected_sid"].split(":")[1])
    return {
        "platform": "linux",
        "expected_profile_id": profile["id"],
        "expected_account_sid": profile["expected_sid"],
        "actual_account_sid": f"uid:{uid}",
        "actual_account_name": profile["account"],
        "uid": uid,
        "euid": uid,
        "gid": uid,
        "egid": uid,
        "groups": [uid],
        "capabilities": "0" * 16,
        "permitted_capabilities": "0" * 16,
        "ambient_capabilities": "0" * 16,
        "bounding_capabilities": "0" * 16,
        "no_new_privileges": True,
        "elevated": uid == 0,
        "process_id": 1234,
        "verified": True,
    }


@pytest.fixture
def sync(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    signer = tmp_path / "signer.pem"
    signer.write_bytes(private)
    app = create_app(
        Settings(
            mode="real",
            database_url=f"sqlite:///{tmp_path}/sync.db",
            signing_key_file=str(signer),
            oidc_issuer="https://id.example.test",
            oidc_jwks_url="https://id.example.test/jwks",
        )
    )
    Base.metadata.create_all(app.state.engine)
    app.dependency_overrides[human] = lambda: Principal(
        "human-admin", frozenset({"viewer", "administrator"}), frozenset()
    )
    actor_id = str(uuid4())
    profile = {
        "id": str(uuid4()),
        "profile_key": "standard-user",
        "account": "atomic-user",
        "expected_sid": "uid:1001",
        "display_name": "Linux standard user",
        "privilege": "standard",
        "logon_type": "systemd",
        "enabled": True,
    }
    with app.state.sessions() as db, db.begin():
        db.add(Actor(id=actor_id, hostname="linux-host-01", os="linux", simulated=False))
        db.flush()
        db.add(Profile(actor_id=actor_id, **profile))
        db.add(Credential(actor_id=actor_id, digest=digest("actor-secret"), expires_at=time.time() + 3600))
    config = {
        "actor_id": actor_id,
        "hostname": "linux-host-01",
        "os": "linux",
        "profiles": [profile],
        "os_version": "Linux",
        "revision": "a" * 40,
        "profile_sync_enabled": True,
    }
    return {
        "app": app,
        "client": TestClient(app),
        "actor": actor_id,
        "profile": profile,
        "config": config,
        "key": private,
        "public": public,
        "agent": {"Authorization": "Bearer actor-secret"},
        "tmp": tmp_path,
    }


def heartbeat(s, protocol=1):
    response = s["client"].post(
        "/api/v1/agents/heartbeat",
        headers=s["agent"],
        json={
            "hostname": "linux-host-01",
            "os": "linux",
            "os_version": "Linux",
            "agent_version": "0.1.0",
            "revision": "a" * 40,
            "profiles": {},
            "health": "healthy",
            "profile_sync_protocol": protocol,
            "profile_config_hash": fingerprint(payload(s["config"])) if protocol else "",
        },
    )
    assert response.status_code == 200, response.text


def poll(s):
    response = s["client"].post("/api/v1/agents/profile-sync/poll", headers=s["agent"])
    assert response.status_code == 200, response.text
    return response.json()["manifest"]


def receipt(s, manifest):
    claims = verify_manifest(manifest, s["config"], s["public"])
    return claims["jti"], {
        "generation": claims["generation"],
        "payload_hash": claims["payload_hash"],
        "error": "",
        "results": {
            p["id"]: {"healthy": True, "identity": evidence(p), "error": ""}
            for p in claims["payload"]["profiles"]
        },
    }


def ack(s, manifest, value=None):
    sync_id, data = receipt(s, manifest)
    response = s["client"].post(
        f"/api/v1/agents/profile-sync/{sync_id}/result", headers=s["agent"], json=value or data
    )
    if response.status_code == 200 and not (value or data).get("error"):
        s["config"]["profiles"] = jwt.decode(manifest, options={"verify_signature": False})["payload"][
            "profiles"
        ]
    return response


def test_capability_reconciliation_signed_payload_and_idempotent_ack(sync):
    s = sync
    heartbeat(s, 0)
    assert s["client"].post(f"/api/v1/actors/{s['actor']}/profile-sync").status_code == 409
    with s["app"].state.sessions() as db:
        assert db.scalar(select(ProfileSync)) is None
    heartbeat(s)
    token = poll(s)
    claims = verify_manifest(token, s["config"], s["public"])
    assert claims["payload"] == payload(s["config"])
    assert set(claims["payload"]) == {"protocol", "actor_id", "hostname", "os", "profiles"}
    assert s["client"].post("/api/v1/agents/jobs/claim", headers=s["agent"]).json() == {"job": None}
    assert ack(s, token).json()["status"] == "applied"
    assert ack(s, token).status_code == 200
    heartbeat(s)
    assert poll(s) is None
    with s["app"].state.sessions() as db:
        assert len(db.scalars(select(ProfileSync)).all()) == 1
        assert db.scalar(select(Run)) is None


def test_add_root_autoqueues_then_partial_failure_and_retry(sync):
    s = sync
    heartbeat(s)
    original = poll(s)
    assert ack(s, original).status_code == 200
    response = s["client"].post(
        f"/api/v1/actors/{s['actor']}/profiles",
        json={
            "profile_key": "local-admin",
            "display_name": "Root",
            "account": "root",
            "expected_sid": "uid:0",
            "privilege": "elevated",
        },
    )
    assert response.status_code == 200, response.text
    root = response.json()
    token = poll(s)
    assert ack(s, original).status_code == 409
    _, data = receipt(s, token)
    data["results"][root["id"]] = {"healthy": False, "identity": None, "error": "probe_failed"}
    assert ack(s, token, data).json()["status"] == "validation_failed"
    heartbeat(s)
    assert poll(s) is None  # Failed probes require explicit retry, no automatic storm.
    response = s["client"].post(f"/api/v1/actors/{s['actor']}/profile-sync")
    assert response.json()["generation"] == 3
    assert ack(s, poll(s)).json()["status"] == "applied"


@pytest.mark.parametrize("change", ["uid", "profile", "caps", "no_new_privileges", "unknown", "missing"])
def test_invalid_kernel_identity_or_result_is_refused(sync, change):
    s = sync
    heartbeat(s)
    token = poll(s)
    _, data = receipt(s, token)
    result = data["results"][s["profile"]["id"]]
    if change == "uid":
        result["identity"]["euid"] = 0
    elif change == "profile":
        result["identity"]["expected_profile_id"] = str(uuid4())
    elif change == "caps":
        result["identity"]["capabilities"] = "0000000000000001"
    elif change == "no_new_privileges":
        result["identity"]["no_new_privileges"] = False
    elif change == "unknown":
        data["results"][str(uuid4())] = data["results"].pop(s["profile"]["id"])
    else:
        data["results"] = {}
    assert ack(s, token, data).status_code == 422


def test_agent_and_human_authorization_boundaries(sync):
    s = sync
    assert s["client"].post("/api/v1/agents/profile-sync/poll").status_code == 401
    heartbeat(s)
    s["app"].dependency_overrides[human] = lambda: Principal(
        "operator", frozenset({"viewer", "operator"}), frozenset()
    )
    assert s["client"].post(f"/api/v1/actors/{s['actor']}/profile-sync").status_code == 403
    s["app"].dependency_overrides[human] = lambda: Principal(
        "mcp", frozenset({"viewer", "administrator"}), frozenset(), True
    )
    assert s["client"].post(f"/api/v1/actors/{s['actor']}/profile-sync").status_code == 403
    other = str(uuid4())
    with s["app"].state.sessions() as db, db.begin():
        db.add(Actor(id=other, hostname="another", os="linux"))
        db.flush()
        db.add(Credential(actor_id=other, digest=digest("other-secret"), expires_at=time.time() + 3600))
    sync_id, data = receipt(s, poll(s))
    response = s["client"].post(
        f"/api/v1/agents/profile-sync/{sync_id}/result",
        headers={"Authorization": "Bearer other-secret"},
        json=data,
    )
    assert response.status_code == 404


def test_existing_lease_including_expired_lease_prevents_profile_dispatch(sync, monkeypatch):
    s = sync
    heartbeat(s)
    # A durable lease is the gate, including an uncertain/expired execution.
    original = s["app"].state.sessions
    with original() as db, db.begin():
        # Disable foreign keys only in this isolated fixture to model a pre-existing lease.
        from sqlalchemy import text

        db.execute(text("PRAGMA foreign_keys=OFF"))
        db.add(
            Lease(
                actor_id=s["actor"],
                run_id=str(uuid4()),
                attempt_id=str(uuid4()),
                fence="f" * 64,
                expires_at=0,
            )
        )
    response = s["client"].post("/api/v1/agents/profile-sync/poll", headers=s["agent"])
    assert response.json() == {"manifest": None, "waiting_for_idle": True}


@pytest.mark.parametrize(
    "change", ["issuer", "audience", "expiry", "hash", "command", "generation", "replay", "key"]
)
def test_agent_rejects_untrusted_or_replayed_profile_manifests(sync, change):
    s = sync
    heartbeat(s)
    token = poll(s)
    claims = jwt.decode(token, options={"verify_signature": False})
    config = copy.deepcopy(s["config"])
    key = s["key"]
    if change == "issuer":
        claims["iss"] = "atomic-control"  # An execution grant cannot configure the agent.
    elif change == "audience":
        claims["aud"] = str(uuid4())
    elif change == "expiry":
        claims["exp"] = time.time() - 1
    elif change == "hash":
        claims["payload_hash"] = "0" * 64
    elif change == "command":
        claims["payload"]["command"] = "MUST NEVER RUN"
    elif change == "generation":
        claims["generation"] = True
    elif change == "replay":
        config["profile_sync_generation"] = 99
    elif change == "key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, key, algorithm="RS256")
    with pytest.raises((ValueError, jwt.PyJWTError)):
        verify_manifest(token, config, s["public"])


def test_agent_apply_preserves_state_and_reacks_without_reprobing(sync, monkeypatch):
    s = sync
    heartbeat(s)
    token = poll(s)
    config = copy.deepcopy(s["config"])
    config.update(
        api_url="https://control.example.test",
        credential_file="/secret/unchanged",
        state_root=str(s["tmp"] / "jobs"),
        public_key_file=str(s["tmp"] / "public.pem"),
        catalog_root="/pinned/catalog",
    )
    Path(config["state_root"]).mkdir()
    Path(config["public_key_file"]).write_text(s["public"])
    path = s["tmp"] / "agent.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(agent_sync, "protected", lambda *a, **kw: None)
    monkeypatch.setattr(
        agent_sync, "write_json", lambda path, value, *a, **kw: path.write_text(json.dumps(value))
    )
    probes = []

    def validate(current, config_file):
        probes.append(True)
        current["profile_validation_results"] = {
            p["id"]: {"healthy": True, "identity": evidence(p), "error": ""} for p in current["profiles"]
        }
        for p in current["profiles"]:
            p["validated"] = True
        config_file.write_text(json.dumps(current))
        return current["profile_validation_results"]

    monkeypatch.setattr(agent_sync, "validate_profiles", validate)
    updated, response = agent_sync.apply_manifest(config, path, token)
    assert not response["result"]["error"] and probes == [True]
    for field in ("api_url", "credential_file", "state_root", "public_key_file", "catalog_root", "revision"):
        assert updated[field] == config[field]
    assert list(path.parent.glob("agent.before-profile-sync-*.json"))
    # Lost ACK: use durable validation receipt rather than run a second probe.
    again, receipt2 = agent_sync.apply_manifest(updated, path, token)
    assert again == updated and receipt2 == response and probes == [True]
    (Path(config["state_root"]) / "active.json").write_text("uncertain")
    with pytest.raises(RuntimeError, match="Unreconciled"):
        agent_sync.apply_manifest(updated, path, token)


def test_profile_drift_and_stalled_apply_can_be_reconciled(sync):
    s = sync
    heartbeat(s)
    token = poll(s)
    assert ack(s, token).status_code == 200
    s["config"]["profiles"] = []
    heartbeat(s)
    with s["app"].state.sessions() as db, db.begin():
        latest = db.scalar(select(ProfileSync).order_by(ProfileSync.generation.desc()))
        assert latest.generation == 2 and latest.status == "pending"
    poll(s)
    with s["app"].state.sessions() as db, db.begin():
        latest = db.scalar(select(ProfileSync).order_by(ProfileSync.generation.desc()))
        latest.updated_at = time.time() - 181
    response = s["client"].post(f"/api/v1/actors/{s['actor']}/profile-sync")
    assert response.json()["generation"] == 3


@pytest.fixture
def update_bundle(sync, tmp_path, monkeypatch):
    import io
    import sys
    import zipfile

    from apps.agent.packaging import update_linux as updater

    response = sync["client"].post(
        f"/api/v1/actors/{sync['actor']}/agent-package",
        json={"api_url": "https://control.example.test", "include_enrollment": False, "catalog_revision": ""},
    )
    assert response.status_code == 200, response.text
    bundle = tmp_path / "bundle"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        archive.extractall(bundle)
    bundle /= "AtomicControlAgent"
    root, state, config = tmp_path / "opt", tmp_path / "state", tmp_path / "etc/agent.json"
    for directory in [
        root / "venv/bin",
        root / "runtime",
        root / "atomic-red-team",
        state / "jobs",
        state / "work",
        state / "secrets",
        config.parent,
    ]:
        directory.mkdir(parents=True)
    (root / "venv/bin/python").write_text("fixture interpreter")
    (root / "job-signing-public.pem").write_text(sync["public"])
    credential = state / "secrets/credential.json"
    credential.write_text("preserved-private-credential")
    credential.chmod(0o600)
    current = {
        **sync["config"],
        "api_url": "https://control.example.test",
        "config_file": str(config),
        "state_root": str(state / "jobs"),
        "work_root": str(state / "work"),
        "credential_file": str(credential),
        "public_key_file": str(root / "job-signing-public.pem"),
        "catalog_root": str(root / "atomic-red-team"),
        "python_path": str(root / "venv/bin/python"),
        "profile_sync_enabled": False,
    }
    config.write_text(json.dumps(current))
    catalog = root / "atomic-red-team/preserved.txt"
    catalog.write_text("existing pinned catalog")
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(updater, "STATE", state)
    monkeypatch.setattr(updater, "CONFIG", config)
    monkeypatch.setattr(updater, "protected", lambda *a: None)
    import subprocess
    from types import SimpleNamespace

    actual_run = subprocess.run
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "import jwt,sys" in str(command):
            # Exercise actual RS256 verification in the test interpreter; no pip/network/systemd.
            return actual_run([sys.executable, *command[1:]], **kwargs)
        if command[0] == "/usr/bin/systemctl":
            return SimpleNamespace(stdout="inactive", returncode=3)
        if "c.update(json.loads(sys.argv[2]))" in str(command):
            value = json.loads(config.read_text())
            value.update(json.loads(command[-1]))
            config.write_text(json.dumps(value))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(updater.subprocess, "run", run)
    return updater, bundle, current, config, credential, catalog, calls


def test_signed_runtime_update_preserves_enrollment_catalog_and_profiles(update_bundle):
    updater, bundle, current, config, credential, catalog, calls = update_bundle
    before = credential.read_bytes(), catalog.read_bytes()
    updater.update(bundle, True, check_only=True)
    assert json.loads(config.read_text()) == current
    assert not any("pip" in command for command in calls)
    updater.update(bundle, True)
    assert json.loads(config.read_text()) == {**current, "profile_sync_enabled": True}
    assert (credential.read_bytes(), catalog.read_bytes()) == before
    assert list(config.parent.glob("agent.before-runtime-update-*.json"))
    assert not any("start" in command or "enroll" in command for command in calls)


def test_runtime_updater_enables_catalog_management_without_replacing_the_pin_or_credentials(update_bundle):
    updater, bundle, current, config, credential, catalog, calls = update_bundle
    before = credential.read_bytes(), catalog.read_bytes()
    updater.update(bundle, True, enable_catalog=True)
    assert json.loads(config.read_text()) == {
        **current,
        "profile_sync_enabled": True,
        "catalog_sync_enabled": True,
    }
    assert (credential.read_bytes(), catalog.read_bytes()) == before


@pytest.mark.parametrize(
    "change", ["manifest", "runtime", "key", "journal", "catalog_journal", "actor", "path"]
)
def test_runtime_update_rejects_tampering_or_unreconciled_work(update_bundle, change):
    import subprocess

    updater, bundle, current, config, credential, catalog, calls = update_bundle
    if change == "manifest":
        manifest = json.loads((bundle / "manifest.json").read_text())
        manifest["files"]["runtime/requirements.txt"] = "0" * 64
        (bundle / "manifest.json").write_text(json.dumps(manifest))
    elif change == "runtime":
        (bundle / "runtime/apps/agent/service.py").write_text("MUST NEVER RUN")
    elif change == "key":
        (updater.ROOT / "job-signing-public.pem").write_text("untrusted")
    elif change == "journal":
        (updater.STATE / "jobs/active.json").write_text("uncertain")
    elif change == "catalog_journal":
        (updater.STATE / "catalog-install.json").write_text("uncertain")
    elif change == "actor":
        current["actor_id"] = str(uuid4())
        config.write_text(json.dumps(current))
    else:
        current["credential_file"] = "/unexpected/path"
        config.write_text(json.dumps(current))
    before = config.read_bytes(), credential.read_bytes(), catalog.read_bytes()
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        updater.update(bundle, True)
    assert (config.read_bytes(), credential.read_bytes(), catalog.read_bytes()) == before
    assert not any("pip" in command for command in calls)


def test_legacy_profile_metadata_can_advertise_capability_and_receive_repair(sync):
    from apps.agent.job_client import heartbeat_payload

    s = sync
    config = copy.deepcopy(s["config"])
    config["profiles"][0].pop("display_name")
    config["profiles"][0].pop("logon_type")
    response = s["client"].post(
        "/api/v1/agents/heartbeat", headers=s["agent"], json=heartbeat_payload(config)
    )
    assert response.status_code == 200, response.text
    assert heartbeat_payload(config)["profile_config_hash"] == "0" * 64
    claims = verify_manifest(poll(s), config, s["public"])
    assert claims["payload"]["profiles"][0]["display_name"] == "Linux standard user"
