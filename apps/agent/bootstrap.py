"""Windows-only package enrollment. Never executes an Atomic test or starts a service."""

import argparse
import json
import os
import platform
import socket
import sys
import time
from pathlib import Path

from .enrollment import enroll
from .execution_broker import restrict_acl


def validate_bundle(bootstrap: dict, config: dict, names: set[str], now: float):
    if bootstrap.get("mode") != "enrollment":
        raise ValueError(
            "Configuration-only package. Generate a fresh enrollment package from a real HTTPS control plane."
        )
    if any(bootstrap.get(k) != config.get(k) for k in ["actor_id", "hostname", "api_url"]):
        raise ValueError("Package actor and configuration do not match")
    if config["hostname"].casefold() not in {name.casefold() for name in names if name}:
        raise ValueError("This package belongs to a different Windows host")
    if (
        not bootstrap.get("enrollment_token")
        or not bootstrap.get("expires_at")
        or bootstrap["expires_at"] <= now
    ):
        raise ValueError("Enrollment token expired. Generate and download a fresh package.")
    if not config["api_url"].startswith("https://"):
        raise ValueError("Agent enrollment requires HTTPS")


def configure(bootstrap_file: Path, config_file: Path, install_root: Path, state_root: Path):
    if os.name != "nt":
        raise RuntimeError("Windows installation is required")
    bootstrap = json.loads(bootstrap_file.read_text(encoding="utf-8-sig"))
    config = json.loads(config_file.read_text(encoding="utf-8-sig"))
    names = {platform.node(), socket.getfqdn(), os.environ.get("COMPUTERNAME", "")}
    validate_bundle(bootstrap, config, names, time.time())
    if not install_root.is_absolute() or not state_root.is_absolute():
        raise ValueError("Use absolute protected installation paths")
    state_root.mkdir(parents=True, exist_ok=True)
    # Profile tasks need directory traversal/read access, but never access to the secrets child.
    import subprocess

    subprocess.run(
        [
            "icacls.exe",
            str(state_root),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
        ],
        check=True,
        capture_output=True,
    )
    config.update(
        state_root=str(state_root / "jobs"),
        credential_file=str(state_root / "secrets" / "credential.dpapi"),
        public_key_file=str(install_root / "job-signing-public.pem"),
        catalog_root=str(install_root / "atomic-red-team"),
        invoke_module_path=str(install_root / "Invoke-AtomicRedTeam" / "Invoke-AtomicRedTeam.psd1"),
        os_version=platform.platform(),
        python_path=sys.executable,
    )
    if config.get("catalog_verification_enabled"):
        from .windows_catalog import manifest, verify_checkout

        config["catalog_manifest_file"] = str(install_root / "catalog-manifest.json")
        value = manifest(json.loads(Path(config["catalog_manifest_file"]).read_text()), config)
        verify_checkout(Path(config["catalog_root"]), value)
    for profile in config["profiles"]:
        profile["validated"] = False
    actor_id = enroll(
        config["api_url"],
        bootstrap["enrollment_token"],
        config["hostname"],
        config["os_version"],
        Path(config["credential_file"]),
        expected_actor_id=config["actor_id"],
    )
    if actor_id != config["actor_id"]:
        raise RuntimeError("Server returned a different actor identity; do not start the service")
    destination = state_root / "agent.json"
    temp = state_root / "agent.json.tmp"
    temp.write_text(json.dumps(config, indent=2))
    restrict_acl(temp, "S-1-5-32-545")
    temp.replace(destination)
    # The archived ZIP may still contain the now-consumed token; do not copy it into the installation.
    bootstrap["enrollment_token"] = None
    bootstrap_file.write_text(json.dumps(bootstrap, indent=2))
    print("Enrolled actor:", actor_id)
    print("Configuration:", destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    args = parser.parse_args()
    configure(args.bootstrap, args.config, args.install_root, args.state_root)
