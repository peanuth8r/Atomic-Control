"""Build a bounded, allowlisted Windows/Linux source/installer ZIP entirely in memory."""

import hashlib
import io
import json
import re
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ..errors import fail
from ..services.token_time import token_issued_at

ROOT = Path(__file__).resolve().parents[4]
AGENT_MODULES = [
    "__init__.py",
    "service.py",
    "enrollment.py",
    "job_client.py",
    "execution_broker.py",
    "identity_validation.py",
    "catalog_validation.py",
    "logging.py",
    "task_wrapper.py",
    "identity_probe.py",
    "bootstrap.py",
    "profile_config.py",
    "windows_profile_sync.py",
    "catalog_config.py",
    "windows_catalog.py",
    "artifacts.py",
    "artifact_execution.py",
    "delivery_migration.py",
    "windows_processes.py",
]
SUPPORT_FILES = [
    "apps/__init__.py",
    "apps/api/__init__.py",
    "apps/api/app/__init__.py",
    "apps/api/app/models/__init__.py",
    "apps/api/app/catalog/parser.py",
    "apps/api/app/catalog/validation.py",
    "apps/api/app/services/common.py",
]
SCRIPTS = [
    "install-agent.ps1",
    "uninstall-agent.ps1",
    "provision-profiles.ps1",
    "require-machine-python.ps1",
    "install-windows-execution-prerequisites.ps1",
]
DEPENDENCIES = {
    "annotated-types",
    "anyio",
    "certifi",
    "cffi",
    "cryptography",
    "h11",
    "httpcore",
    "httpx",
    "idna",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "pyjwt",
    "pyyaml",
    "sqlalchemy",
    "typing-extensions",
    "typing-inspection",
}


def read_source(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        fail("package_source_unavailable", "An agent package source file is unavailable", 503)
    return path.read_bytes()


def public_key(settings) -> str:
    if not settings.signing_key_file:
        fail(
            "signing_key_unavailable",
            "Configure the RSA job-signing key before generating agent packages",
            503,
        )
    try:
        key = serialization.load_pem_private_key(Path(settings.signing_key_file).read_bytes(), password=None)
        if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("Invalid signing key")
        return (
            key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
    except (OSError, ValueError, TypeError):
        fail(
            "signing_key_unavailable",
            "A valid RSA job-signing key is required to generate an enrollment package",
            503,
        )


def public_ca(settings, api_url=None):
    """Read only the explicitly configured single public root, never a process trust bundle."""
    path = settings.agent_public_ca_file
    if not path:
        return None
    if api_url is not None and api_url.rstrip("/") != settings.public_url.rstrip("/"):
        fail("ca_origin_mismatch", "Bundled CA packages must use the configured control-plane URL", 422)
    try:
        raw = read_source(Path(path))
        if len(raw) > 32768:
            raise ValueError("Certificate too large")
        cert = x509.load_pem_x509_certificate(raw)
        pem = cert.public_bytes(serialization.Encoding.PEM)
        if raw.replace(b"\r\n", b"\n").strip() != pem.strip():
            raise ValueError("Expected one public certificate only")
        now = datetime.now(UTC)
        if (
            not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            or cert.issuer != cert.subject
            or not cert.not_valid_before_utc <= now < cert.not_valid_after_utc
        ):
            raise ValueError("Expected a current self-signed CA")
        cert.verify_directly_issued_by(cert)
        return pem, {
            "filename": "atomic-control-ca.crt",
            "subject": cert.subject.rfc4514_string(),
            "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "store": "LocalMachine\\Root",
        }
    except (OSError, ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
        fail(
            "agent_ca_invalid",
            "Configure one valid public self-signed CA certificate in ATOMIC_AGENT_PUBLIC_CA_FILE",
            503,
        )


def build_package(
    actor,
    profiles,
    data,
    settings,
    token: str | None,
    expires_at: float | None,
    catalog=None,
    enrollment_seconds: int = 3600,
) -> tuple[bytes, str]:
    key = public_key(settings)
    if token and not key:
        fail(
            "signing_key_unavailable",
            "Configure the RSA job-signing key before generating enrollment packages",
            503,
        )
    if actor.os not in {"windows", "linux"}:
        fail("unsupported_platform", "Only Windows and Linux agent packages are supported", 422)
    linux = actor.os == "linux"
    on_demand = data.delivery_mode == "on_demand"
    if on_demand and data.catalog_revision:
        fail("invalid_catalog_mode", "On-demand packages do not install a catalog revision", 422)
    if not linux and data.catalog_revision and catalog is None:
        fail("catalog_manifest_required", "Selected Windows catalogs need imported definition metadata", 422)
    ca = None if linux else public_ca(settings, data.api_url)
    mode = "enrollment" if token else "configuration_only"
    config = {
        "profile_sync_enabled": True,
        "delivery_mode": data.delivery_mode,
        "artifact_preparation_seconds": settings.artifact_preparation_seconds,
        "os": actor.os,
        "api_url": data.api_url,
        "actor_id": actor.id,
        "hostname": actor.hostname,
        "os_version": "Windows",
        "state_root": r"C:\ProgramData\AtomicControl\jobs",
        "credential_file": r"C:\ProgramData\AtomicControl\secrets\credential.dpapi",
        "public_key_file": r"C:\Program Files\AtomicControl\job-signing-public.pem",
        "catalog_root": r"C:\Program Files\AtomicControl\atomic-red-team",
        "revision": data.catalog_revision,
        "powershell_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "invoke_module_path": r"C:\Program Files\AtomicControl\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psd1",
        "invoke_module_sha256": "REPLACE_WITH_REVIEWED_MODULE_SHA256",
        "heartbeat_seconds": 30,
        "poll_seconds": 5,
        "profiles": [
            {
                "id": p.id,
                "profile_key": p.profile_key,
                "display_name": p.display_name,
                "account": p.account,
                "expected_sid": p.expected_sid,
                "privilege": p.privilege,
                "logon_type": p.logon_type,
                "enabled": p.enabled,
                "validated": False,
            }
            for p in profiles
        ],
    }
    if linux:
        config.update(
            profile_sync_enabled=True,
            catalog_sync_enabled=not on_demand,
            os_version="Linux",
            state_root="/var/lib/atomic-control/jobs",
            work_root="/var/lib/atomic-control/work",
            config_file="/etc/atomic-control/agent.json",
            credential_file="/var/lib/atomic-control/secrets/credential.json",
            public_key_file="/opt/atomic-control/job-signing-public.pem",
            catalog_root="/opt/atomic-control/atomic-red-team",
            python_path="/opt/atomic-control/venv/bin/python",
        )
        for field in ["powershell_path", "invoke_module_path", "invoke_module_sha256"]:
            config.pop(field)
    payload: dict[str, bytes] = {}
    if ca:
        payload["atomic-control-ca.crt"] = ca[0]
    if not linux and catalog and not on_demand:
        from apps.agent.windows_catalog import manifest as validate_package_catalog

        catalog = validate_package_catalog(catalog, config)
        payload["catalog.json"] = json.dumps(catalog, sort_keys=True).encode()
        config["catalog_verification_enabled"] = True
    for name in SUPPORT_FILES:
        payload["runtime/" + name] = read_source(ROOT / name)
    for name in AGENT_MODULES:
        payload["runtime/apps/agent/" + name] = read_source(ROOT / "apps/agent" / name)
    if linux:
        for name in [
            "__init__.py",
            "security.py",
            "identity.py",
            "commands.py",
            "runner.py",
            "broker.py",
            "probe.py",
            "service.py",
            "bootstrap.py",
            "profile_sync.py",
            "catalog_sync.py",
        ]:
            payload["runtime/apps/agent/linux/" + name] = read_source(ROOT / "apps/agent/linux" / name)
    else:
        for name in ["invoke_approved_atomic.ps1", "verify_identity.ps1", "AtomicControlLogger.psm1"]:
            payload["runtime/apps/agent/powershell/" + name] = read_source(
                ROOT / "apps/agent/powershell" / name
            )
        for name in SCRIPTS:
            payload["runtime/scripts/" + name] = read_source(ROOT / "scripts" / name)
    # Explicit empty package initializers make installed support imports unambiguous.
    for name in ["apps/api/app/catalog/__init__.py", "apps/api/app/services/__init__.py"]:
        payload["runtime/" + name] = b""
    requirements = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        if line.split("==", 1)[0].lower().replace("_", "-") in DEPENDENCIES:
            requirements.append(line)
    if len(requirements) != len(DEPENDENCIES):
        fail(
            "package_dependencies_unavailable",
            "Pinned agent runtime dependency definitions are incomplete",
            503,
        )
    requirements += ([] if linux else ['pywin32>=311; sys_platform == "win32"']) + ["setuptools==82.0.1"]
    payload["runtime/requirements.txt"] = ("\n".join(requirements) + "\n").encode()
    payload["runtime/requirements-agent.txt"] = b"-r requirements.txt\n"
    payload["runtime/pyproject.toml"] = b"""[build-system]
requires = ["setuptools==82.0.1"]
build-backend = "setuptools.build_meta"
[project]
name = "atomic-control-agent"
version = "0.2.0"
requires-python = ">=3.12"
[tool.setuptools.packages.find]
include = ["apps*"]
[tool.setuptools.package-data]
"apps.agent" = ["powershell/*.ps1", "powershell/*.psm1"]
"""
    payload["agent.json"] = json.dumps(config, indent=2).encode()
    payload["bootstrap.json"] = json.dumps(
        {
            "actor_id": actor.id,
            "os": actor.os,
            "hostname": actor.hostname,
            "api_url": data.api_url,
            "mode": mode,
            "enrollment_token": token,
            "expires_at": expires_at,
            "token_lifetime_seconds": enrollment_seconds if token else None,
            "public_ca": ca[1] if ca else None,
        },
        indent=2,
    ).encode()
    if linux:
        for target, source in {
            "Install-Agent.sh": "Install-Agent.sh",
            "install.py": "install_linux.py",
            "Update-Agent.py": "update_linux.py",
            "atomic-control-agent.service": "atomic-control-agent.service",
        }.items():
            payload[target] = read_source(ROOT / "apps/agent/packaging" / source)
    else:
        payload["Update-Agent.py"] = read_source(ROOT / "apps/agent/packaging/update_windows.py")
        payload["Install-Agent.ps1"] = read_source(ROOT / "apps/agent/packaging/Install-Agent.ps1")
    template = read_source(
        ROOT / "apps/agent/packaging" / ("README-linux.txt" if linux else "README.txt")
    ).decode()
    payload["README.txt"] = (
        f"ACTOR: {actor.hostname}\nACTOR ID: {actor.id}\nPACKAGE: {mode}\nSERVER: {data.api_url}\n"
        + (
            f"Enrollment token expires {enrollment_seconds // 60} minutes after generation and is single-use.\n"
            if token
            else "No enrollment credential is included. This package cannot enroll a real host.\n"
        )
        + (
            "\nDELIVERY: on-demand. No full catalog or Git required; Run or Queue prepares approved test files automatically.\n"
            if on_demand
            else "\nDELIVERY: pinned checkout.\n"
        )
        + template
    ).encode()
    payload["job-signing-public.pem"] = key.encode()
    manifest = {
        "actor_id": actor.id,
        "os": actor.os,
        "hostname": actor.hostname,
        "mode": mode,
        "agent_version": "0.2.0",
        "generated_at": time.time(),
        "enrollment_expires_at": expires_at,
        "files": {name: hashlib.sha256(content).hexdigest() for name, content in sorted(payload.items())},
    }
    payload["manifest.json"] = json.dumps(manifest, indent=2).encode()
    if key:
        payload["manifest.jwt"] = jwt.encode(
            {
                "iss": "atomic-control-package",
                "aud": actor.id,
                "iat": token_issued_at(),
                "exp": time.time() + 604800,
                "type": "linux-runtime-package-v1" if linux else "windows-runtime-package-v1",
                "manifest_sha256": hashlib.sha256(payload["manifest.json"]).hexdigest(),
            },
            Path(settings.signing_key_file).read_text(),
            algorithm="RS256",
        ).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(payload.items()):
            archive.writestr("AtomicControlAgent/" + name, content)
    filename = "AtomicControlAgent-" + re.sub(r"[^A-Za-z0-9._-]", "_", actor.hostname) + ".zip"
    return stream.getvalue(), filename
