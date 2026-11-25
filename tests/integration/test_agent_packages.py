import hashlib
import io
import json
import subprocess
import sys
import time
import zipfile
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.agent.bootstrap import validate_bundle
from apps.api.app.auth import Principal, human
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import Actor, Audit, Base, Credential, Enrollment
from apps.api.app.services.common import digest

ADMIN = {"X-Test-User": "admin"}
URL = "https://control.example.test"


def unpack(response):
    assert response.status_code == 200, response.text
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    assert archive.testzip() is None
    return {name.removeprefix("AtomicControlAgent/"): archive.read(name) for name in archive.namelist()}


def generate(env, actor=None, enrollment=False, url=URL, **extra):
    return env["client"].post(
        f"/api/v1/actors/{actor or env['actor']}/agent-package",
        headers=ADMIN,
        json={"api_url": url, "include_enrollment": enrollment, **extra},
    )


def register(client, hostname="WIN-PACKAGE-01", headers=None):
    response = client.post("/api/v1/actors", headers=headers or ADMIN, json={"hostname": hostname})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def real(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    key_file = tmp_path / "signer.pem"
    key_file.write_bytes(private)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/real.db",
        mode="real",
        dev_auth=False,
        signing_key_file=str(key_file),
        oidc_issuer="https://id.example.test",
        oidc_jwks_url="https://id.example.test/jwks",
        public_url=URL,
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    app.dependency_overrides[human] = lambda: Principal(
        "human:administrator", frozenset({"administrator", "viewer"}), frozenset()
    )
    return {"app": app, "settings": settings, "client": TestClient(app), "private_key": private}


def test_actor_specific_zip_allowlist_integrity_no_server_secrets(env):
    response = generate(env)
    files = unpack(response)
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-package-sha256"] == hashlib.sha256(response.content).hexdigest()
    assert response.headers["x-package-mode"] == "configuration_only"
    manifest, config, bootstrap = [
        json.loads(files[name]) for name in ["manifest.json", "agent.json", "bootstrap.json"]
    ]
    assert manifest["actor_id"] == env["actor"] == config["actor_id"] == bootstrap["actor_id"]
    assert config["hostname"] == "WIN-TEST-01" and config["api_url"] == URL
    assert len(config["profiles"]) == 2 and all(not p["validated"] for p in config["profiles"])
    assert bootstrap["enrollment_token"] is None and bootstrap["mode"] == "configuration_only"
    assert {
        "Install-Agent.ps1",
        "runtime/apps/agent/bootstrap.py",
        "runtime/apps/agent/service.py",
        "runtime/apps/agent/powershell/invoke_approved_atomic.ps1",
        "runtime/scripts/require-machine-python.ps1",
        "runtime/scripts/install-windows-execution-prerequisites.ps1",
        "README.txt",
    } <= files.keys()
    for name, expected in manifest["files"].items():
        assert hashlib.sha256(files[name]).hexdigest() == expected
    assert all(
        not (
            ".env" in name
            or name.endswith(".key")
            or "signer.pem" in name
            or "auth/" in name
            or "routes/" in name
            or "fixtures/" in name
            or "atomic-red-team/" in name
        )
        for name in files
    )
    requirements = files["runtime/requirements.txt"].decode()
    assert (
        "pywin32>=311" in requirements
        and "PyYAML==6.0.4" in requirements
        and "SQLAlchemy==" in requirements
        and "pytest" not in requirements
        and "mcp==" not in requirements
    )
    with env["app"].state.sessions() as db:
        assert db.scalar(select(Audit).where(Audit.action == "agent.package-generated"))


def test_new_actor_reserved_then_downloaded_without_fake_online_state(env):
    actor = register(env["client"])
    assert (
        actor["registration_state"] == "pending_enrollment"
        and not actor["online"]
        and actor["profiles"] == []
    )
    config = json.loads(unpack(generate(env, actor["id"]))["agent.json"])
    assert config["actor_id"] == actor["id"] and config["profiles"] == []
    assert (
        env["client"]
        .post("/api/v1/actors", headers=ADMIN, json={"hostname": actor["hostname"].lower()})
        .status_code
        == 409
    )


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_only_administrators_can_register_and_generate_packages(env, role):
    headers = {"X-Test-User": role}
    assert (
        env["client"].post("/api/v1/actors", headers=headers, json={"hostname": "WIN-NEW"}).status_code == 403
    )
    assert env["client"].get("/api/v1/agents/package-options", headers=headers).status_code == 403
    assert (
        env["client"]
        .post(f"/api/v1/actors/{env['actor']}/agent-package", headers=headers, json={"api_url": URL})
        .status_code
        == 403
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://control.example.test",
        "https://user:password@control.example.test",
        "https://control.example.test/path",
        "https://control.example.test?secret=1",
        "https://host name",
        "https://host:99999",
    ],
)
def test_invalid_package_urls_rejected(env, url):
    assert generate(env, url=url).status_code == 422


def test_legacy_fixture_actor_cannot_receive_enrollment_credentials(env):
    with env["app"].state.sessions() as db, db.begin():
        db.get(Actor, env["actor"]).simulated = True
    response = generate(env, enrollment=True)
    assert response.status_code == 409 and response.json()["error"]["code"] == "actor_unavailable"
    with env["app"].state.sessions() as db:
        assert not db.scalars(select(Enrollment)).all()


def test_real_bundle_only_contains_public_key_and_short_lived_actor_token(real):
    actor = register(real["client"])
    response = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
    )
    files = unpack(response)
    assert response.headers["x-package-mode"] == "enrollment"
    assert real["private_key"] not in response.content
    assert all(b"BEGIN PRIVATE KEY" not in value for value in files.values())
    public = serialization.load_pem_public_key(files["job-signing-public.pem"])
    private = serialization.load_pem_private_key(real["private_key"], None)
    assert public.public_numbers() == private.public_key().public_numbers()
    bootstrap = json.loads(files["bootstrap.json"])
    assert time.time() < bootstrap["expires_at"] <= time.time() + 3600
    with real["app"].state.sessions() as db:
        token = db.scalar(select(Enrollment).where(Enrollment.actor_id == actor["id"]))
        assert (
            token.digest == digest(bootstrap["enrollment_token"])
            and token.digest != bootstrap["enrollment_token"]
        )
    body = {
        "token": bootstrap["enrollment_token"],
        "hostname": actor["hostname"],
        "os_version": "Windows 11",
        "agent_version": "0.1.0",
    }
    assert (
        real["client"].post("/api/v1/agents/enroll", json={**body, "hostname": "WRONG-HOST"}).status_code
        == 401
    )
    enrolled = real["client"].post("/api/v1/agents/enroll", json=body)
    assert enrolled.status_code == 200 and enrolled.json()["actor_id"] == actor["id"]
    assert real["client"].post("/api/v1/agents/enroll", json=body).status_code == 401
    assert real["client"].get(f"/api/v1/actors/{actor['id']}").json()["registration_state"] == "enrolled"


def test_regenerating_bundle_invalidates_older_unused_tokens(real):
    actor = register(real["client"])
    values = []
    for _ in range(2):
        response = real["client"].post(
            f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
        )
        values.append(json.loads(unpack(response)["bootstrap.json"]))
    body = {"hostname": actor["hostname"], "agent_version": "0.1.0", "os_version": "Windows"}
    assert (
        real["client"]
        .post("/api/v1/agents/enroll", json={**body, "token": values[0]["enrollment_token"]})
        .status_code
        == 401
    )
    assert (
        real["client"]
        .post("/api/v1/agents/enroll", json={**body, "token": values[1]["enrollment_token"]})
        .status_code
        == 200
    )


def test_replacement_requires_disabled_actor_and_revokes_old_credentials_only_on_enrollment(real):
    actor = register(real["client"])
    first = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
    )
    boot = json.loads(unpack(first)["bootstrap.json"])
    body = {"hostname": actor["hostname"], "agent_version": "0.1.0", "os_version": "Windows"}
    old = (
        real["client"]
        .post("/api/v1/agents/enroll", json={**body, "token": boot["enrollment_token"]})
        .json()["credential"]
    )
    assert (
        real["client"]
        .post(
            f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
        )
        .json()["error"]["code"]
        == "actor_must_be_disabled"
    )
    real["client"].post(f"/api/v1/actors/{actor['id']}/disable").raise_for_status()
    second = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
    )
    boot = json.loads(unpack(second)["bootstrap.json"])
    with real["app"].state.sessions() as db:
        assert not db.scalar(select(Credential).where(Credential.digest == digest(old))).revoked
    real["client"].post(
        "/api/v1/agents/enroll", json={**body, "token": boot["enrollment_token"]}
    ).raise_for_status()
    with real["app"].state.sessions() as db:
        assert db.scalar(select(Credential).where(Credential.digest == digest(old))).revoked
        assert not db.get(Actor, actor["id"]).enabled


def test_active_or_uncertain_actor_lease_blocks_new_identity(env, approved_job):
    from apps.api.app.models import Lease

    assert env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={}).json()["job"]
    with env["app"].state.sessions() as db, db.begin():
        actor = db.get(Actor, env["actor"])
        actor.simulated, actor.enabled = False, False
        db.get(Lease, actor.id).expires_at = 0
    env["settings"].mode = "real"
    env["settings"].public_url = URL
    response = generate(env, enrollment=True)
    assert response.json()["error"]["code"] == "actor_busy"


def test_package_failure_does_not_issue_a_dangling_token(real, monkeypatch):
    actor = register(real["client"])
    from apps.api.app.errors import fail

    monkeypatch.setattr(
        "apps.api.app.routes.agent_packages.build_package",
        lambda *_, **kwargs: fail("package_source_unavailable", "Source unavailable", 503),
    )
    response = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
    )
    assert response.status_code == 503
    with real["app"].state.sessions() as db:
        assert not db.scalars(select(Enrollment)).all()


def test_bootstrap_rejects_wrong_host_expired_or_mixed_identity_before_network():
    actor = str(uuid4())
    boot = {
        "mode": "enrollment",
        "actor_id": actor,
        "hostname": "WIN-ONE",
        "api_url": URL,
        "enrollment_token": "x" * 64,
        "expires_at": 1000,
    }
    config = {k: boot[k] for k in ["actor_id", "hostname", "api_url"]}
    validate_bundle(boot, config, {"win-one"}, 900)
    with pytest.raises(ValueError, match="different Windows host"):
        validate_bundle(boot, config, {"WIN-TWO"}, 900)
    with pytest.raises(ValueError, match="expired"):
        validate_bundle(boot, config, {"WIN-ONE"}, 1001)
    with pytest.raises(ValueError, match="do not match"):
        validate_bundle(boot, {**config, "actor_id": str(uuid4())}, {"WIN-ONE"}, 900)
    with pytest.raises(ValueError, match="Configuration-only"):
        validate_bundle({**boot, "mode": "configuration_only"}, config, {"WIN-ONE"}, 900)


def test_generated_runtime_imports_without_control_plane_or_project_files(env, tmp_path):
    files = unpack(generate(env))
    runtime = tmp_path / "runtime"
    for name, data in files.items():
        if name.startswith("runtime/"):
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    code = "import sys;sys.path.insert(0,sys.argv[1]);import apps.agent.service,apps.agent.bootstrap,apps.agent.task_wrapper;print('imports ok')"
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(runtime)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == "imports ok"


def test_real_package_url_cannot_send_enrollment_to_a_different_control_plane(real):
    actor = register(real["client"])
    response = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package",
        json={"api_url": "https://other.example.test", "include_enrollment": True},
    )
    assert response.json()["error"]["code"] == "control_plane_url_mismatch"
    with real["app"].state.sessions() as db:
        assert not db.scalars(select(Enrollment)).all()


def test_expired_packaged_token_cannot_enroll(real):
    actor = register(real["client"])
    response = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
    )
    bootstrap = json.loads(unpack(response)["bootstrap.json"])
    with real["app"].state.sessions() as db, db.begin():
        db.scalar(select(Enrollment).where(Enrollment.actor_id == actor["id"])).expires_at = 0
    enrolled = real["client"].post(
        "/api/v1/agents/enroll",
        json={
            "hostname": actor["hostname"],
            "agent_version": "0.1.0",
            "os_version": "Windows",
            "token": bootstrap["enrollment_token"],
        },
    )
    assert enrolled.status_code == 401
    assert (
        real["client"].get(f"/api/v1/actors/{actor['id']}").json()["registration_state"]
        == "pending_enrollment"
    )


def test_bootstrap_rejects_an_unexpected_server_identity_before_saving_credentials(monkeypatch, tmp_path):
    from types import SimpleNamespace

    import httpx

    from apps.agent import enrollment

    monkeypatch.setattr(enrollment, "os", SimpleNamespace(name="nt"))
    response = httpx.Response(
        200,
        json={"actor_id": str(uuid4()), "credential": "not-saved", "expires_at": time.time() + 3600},
        request=httpx.Request("POST", URL + "/api/v1/agents/enroll"),
    )
    monkeypatch.setattr(enrollment.httpx, "post", lambda *_, **__: response)

    def forbidden(*_):
        raise AssertionError("Unexpected actor credentials must never be written")

    monkeypatch.setattr(enrollment, "save_credential", forbidden)
    with pytest.raises(RuntimeError, match="different actor identity"):
        enrollment.enroll(
            URL,
            "x" * 64,
            "WIN-TEST",
            "Windows",
            tmp_path / "credential.dpapi",
            expected_actor_id=str(uuid4()),
        )


def test_linux_package_registration_installer_and_isolated_runtime(env, tmp_path):
    response = env["client"].post(
        "/api/v1/actors", headers=ADMIN, json={"hostname": "linux-package-one", "os": "linux"}
    )
    assert response.status_code == 201
    actor = response.json()
    assert actor["os"] == "linux" and not actor["online"]
    files = unpack(generate(env, actor["id"]))
    config = json.loads(files["agent.json"])
    assert config["os"] == "linux" and config["credential_file"].endswith("/secrets/credential.json")
    assert "powershell_path" not in config and config["profiles"] == []
    assert {
        "install.py",
        "Install-Agent.sh",
        "atomic-control-agent.service",
        "runtime/apps/agent/linux/runner.py",
    } <= files.keys()
    assert "Install-Agent.ps1" not in files and "pywin32" not in files["runtime/requirements.txt"].decode()
    manifest = json.loads(files["manifest.json"])
    assert manifest["os"] == "linux"
    for name, expected in manifest["files"].items():
        assert hashlib.sha256(files[name]).hexdigest() == expected
    for name, data in files.items():
        if name.startswith("runtime/"):
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys;sys.path.insert(0,sys.argv[1]);import apps.agent.linux.runner,apps.agent.linux.broker,apps.agent.linux.bootstrap,apps.agent.linux.service,apps.agent.linux.catalog_sync;print('linux imports ok')",
            str(tmp_path / "runtime"),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == "linux imports ok"


def test_linux_enrollment_is_bound_to_actor_os_and_profiles_are_uid_based(real):
    response = real["client"].post("/api/v1/actors", json={"hostname": "linux-real-one", "os": "linux"})
    actor = response.json()
    body = {
        "profile_key": "standard-user",
        "display_name": "Linux user",
        "account": "atomic-user",
        "expected_sid": "uid:1001",
        "privilege": "standard",
    }
    endpoint = f"/api/v1/actors/{actor['id']}/profiles"
    assert real["client"].post(endpoint, json={**body, "expected_sid": "S-1-5-21-1"}).status_code == 422
    assert real["client"].post(endpoint, json={**body, "expected_sid": "uid:0"}).status_code == 422
    profile = real["client"].post(endpoint, json=body)
    assert profile.status_code == 200 and profile.json()["logon_type"] == "systemd"
    response = real["client"].post(
        f"/api/v1/actors/{actor['id']}/agent-package", json={"api_url": URL, "include_enrollment": True}
    )
    files = unpack(response)
    boot = json.loads(files["bootstrap.json"])
    assert boot["os"] == "linux"
    assert json.loads(files["agent.json"])["profiles"][0]["expected_sid"] == "uid:1001"
    enrollment = {
        "token": boot["enrollment_token"],
        "hostname": actor["hostname"],
        "os_version": "Linux",
        "agent_version": "0.1.0",
    }
    assert real["client"].post("/api/v1/agents/enroll", json=enrollment).status_code == 401
    response = real["client"].post("/api/v1/agents/enroll", json={**enrollment, "os": "linux"})
    assert response.status_code == 200 and response.json()["actor_id"] == actor["id"]
    assert real["client"].get(f"/api/v1/actors/{actor['id']}").json()["os"] == "linux"


def test_generic_linux_enrollment_token_preserves_platform(real):
    token = (
        real["client"]
        .post("/api/v1/enrollment-tokens", json={"hostname": "linux-generic", "os": "linux"})
        .json()["token"]
    )
    response = real["client"].post(
        "/api/v1/agents/enroll",
        json={
            "token": token,
            "hostname": "linux-generic",
            "os": "linux",
            "os_version": "Linux",
            "agent_version": "0.1.0",
        },
    )
    assert response.status_code == 200
    actor = real["client"].get(f"/api/v1/actors/{response.json()['actor_id']}").json()
    assert actor["os"] == "linux"


@pytest.fixture
def bundled_ca(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Atomic fixture public CA")])
    now = datetime.now(UTC)

    def issue(*, ca=True, expired=False, key_cert_sign=True):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=key_cert_sign,
                    crl_sign=key_cert_sign,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

    cert = issue()
    path = tmp_path / "public-ca.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path, cert, key, issue


def test_windows_package_includes_exact_public_ca_and_fingerprint_bound_by_manifest(real, bundled_ca):
    from cryptography.hazmat.primitives import hashes

    path, cert, key, _ = bundled_ca
    real["settings"].agent_public_ca_file = str(path)
    actor = register(real["client"])
    response = real["client"].get("/api/v1/agents/package-options")
    assert response.status_code == 200
    info = response.json()["public_ca"]
    assert info["sha256"] == cert.fingerprint(hashes.SHA256()).hex().upper()
    assert info["store"] == "LocalMachine\\Root"
    package = unpack(generate(real, actor=actor["id"], enrollment=True))
    assert package["atomic-control-ca.crt"] == path.read_bytes()
    assert json.loads(package["bootstrap.json"])["public_ca"] == info
    manifest = json.loads(package["manifest.json"])
    assert manifest["files"]["atomic-control-ca.crt"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert all(b"PRIVATE KEY" not in content for content in package.values())
    assert all(not name.endswith(".pfx") and "ca-key" not in name for name in package)


@pytest.mark.parametrize(
    "invalid", ["private-key", "combined", "leaf", "expired", "not-signing", "symlink", "garbage"]
)
def test_invalid_or_nonpublic_ca_refuses_package_without_committing_enrollment(real, bundled_ca, invalid):
    path, cert, key, issue = bundled_ca
    pem = cert.public_bytes(serialization.Encoding.PEM)
    if invalid == "private-key":
        path.write_bytes(
            pem
            + key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    elif invalid == "combined":
        path.write_bytes(pem + pem)
    elif invalid == "leaf":
        path.write_bytes(issue(ca=False).public_bytes(serialization.Encoding.PEM))
    elif invalid == "expired":
        path.write_bytes(issue(expired=True).public_bytes(serialization.Encoding.PEM))
    elif invalid == "not-signing":
        path.write_bytes(issue(key_cert_sign=False).public_bytes(serialization.Encoding.PEM))
    elif invalid == "garbage":
        path.write_text("not a certificate")
    elif invalid == "symlink":
        link = path.with_name("linked-ca.crt")
        link.symlink_to(path)
        path = link
    real["settings"].agent_public_ca_file = str(path)
    actor = register(real["client"])
    response = generate(real, actor=actor["id"], enrollment=True)
    assert response.status_code == 503, response.text
    with real["app"].state.sessions() as db:
        assert not list(db.scalars(select(Enrollment).where(Enrollment.actor_id == actor["id"])))


def test_public_ca_is_not_inferred_from_process_trust_bundle(real, bundled_ca, monkeypatch):
    path, *_ = bundled_ca
    monkeypatch.setenv("SSL_CERT_FILE", str(path))
    actor = register(real["client"])
    package = unpack(generate(real, actor=actor["id"], enrollment=True))
    assert "atomic-control-ca.crt" not in package
    assert json.loads(package["bootstrap.json"])["public_ca"] is None


def test_bundled_ca_cannot_be_repurposed_for_another_api_origin(real, bundled_ca):
    path, *_ = bundled_ca
    real["settings"].agent_public_ca_file = str(path)
    actor = register(real["client"])
    response = generate(real, actor=actor["id"], url="https://other.example.test")
    assert response.status_code == 422 and response.json()["error"]["code"] == "ca_origin_mismatch"


def test_selected_windows_catalog_is_bound_to_actor_and_imported_hashes(env):
    from apps.api.app.models import AtomicTest

    with env["app"].state.sessions() as db:
        test = db.scalar(select(AtomicTest).where(AtomicTest.active.is_(True)))
        revision = test.revision
        expected = {"guid": test.guid, "technique": test.technique, "sha256": test.content_hash}
    package = unpack(generate(env, catalog_revision=revision))
    config = json.loads(package["agent.json"])
    catalog = json.loads(package["catalog.json"])
    assert config["catalog_verification_enabled"]
    assert catalog["actor_id"] == env["actor"] and catalog["revision"] == revision
    assert expected in catalog["tests"] and catalog["source"] == "redcanaryco/atomic-red-team"
    assert "runtime/apps/agent/windows_catalog.py" in package
    manifest = json.loads(package["manifest.json"])
    assert manifest["files"]["catalog.json"] == hashlib.sha256(package["catalog.json"]).hexdigest()


def test_enrollment_only_windows_package_does_not_claim_a_catalog_pin(env):
    package = unpack(generate(env))
    config = json.loads(package["agent.json"])
    assert config["revision"] == "" and not config.get("catalog_verification_enabled")
    assert "catalog.json" not in package


@pytest.mark.parametrize("sync_enabled", [False, True])
def test_windows_in_place_update_enables_sync_without_reenrollment(real, tmp_path, monkeypatch, sync_enabled):
    """Validate a real signed ZIP with native installation commands replaced."""
    import ctypes
    from types import SimpleNamespace

    from apps.agent.packaging import update_windows as updater

    actor = register(real["client"])
    files = unpack(generate(real, actor=actor["id"]))
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name, raw in files.items():
        target = bundle / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    program = tmp_path / "ProgramFiles"
    statebase = tmp_path / "ProgramData"
    root = program / "AtomicControl"
    state = statebase / "AtomicControl"
    root.mkdir(parents=True)
    state.mkdir(parents=True)
    (root / "job-signing-public.pem").write_bytes(files["job-signing-public.pem"])
    credential = state / "credential"
    credential.write_bytes(b"original-enrolled-credential")
    profile = {"id": str(uuid4()), "account": "existing-user", "validated": True}
    config = {
        **json.loads(files["agent.json"]),
        "profile_sync_enabled": sync_enabled,
        "python_path": r"C:\Users\example\AppData\Local\Python\python.exe",
        "state_root": str(state / "jobs"),
        "public_key_file": str(root / "job-signing-public.pem"),
        "credential_file": str(credential),
        "profiles": [profile],
    }
    config_file = state / "agent.json"
    config_file.write_text(json.dumps(config))
    python = tmp_path / "python.exe"
    python.write_bytes(b"protected-python-placeholder")
    monkeypatch.setattr(
        ctypes, "windll", SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True)), raising=False
    )
    monkeypatch.setattr(
        updater,
        "os",
        SimpleNamespace(name="nt", environ={"ProgramFiles": str(program), "ProgramData": str(statebase)}),
    )
    monkeypatch.setattr(updater, "sys", SimpleNamespace(executable=str(python)))
    monkeypatch.setattr(updater, "require_machine_python", lambda value: None)
    script_dir = tmp_path / "Scripts"
    script_dir.mkdir()
    (script_dir / "pywin32_postinstall.py").write_text("# native command is mocked")
    monkeypatch.setattr(updater, "sysconfig", SimpleNamespace(get_path=lambda value: str(script_dir)))
    calls = []

    def native(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command, 0, stdout="STATE: STOPPED" if command[0] == "sc.exe" else ""
        )

    monkeypatch.setattr(updater, "subprocess", SimpleNamespace(run=native))
    updater.update(bundle, check_only=True)
    assert json.loads(config_file.read_text()) == config
    updater.update(bundle)
    changed = json.loads(config_file.read_text())
    assert changed["profile_sync_enabled"] is True and changed["python_path"] == str(python)
    assert changed["profiles"] == [profile] and changed["actor_id"] == config["actor_id"]
    assert credential.read_bytes() == b"original-enrolled-credential"
    assert (root / "job-signing-public.pem").read_bytes() == files["job-signing-public.pem"]
    assert any("pip" in call for call in calls)
    assert [str(python), "-I", "-m", "apps.agent.service", "--startup", "auto", "update"] in calls
    assert [str(python), "-I", str(script_dir / "pywin32_postinstall.py"), "-install"] in calls
