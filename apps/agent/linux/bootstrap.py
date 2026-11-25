"""Enroll a Linux package without running a test or starting a service."""

import argparse
import json
import os
import platform
import socket
import sys
import time
from pathlib import Path

from ..enrollment import enroll
from .security import protected, write_json


def validate_bundle(bootstrap: dict, config: dict, names: set[str], now: float):
    if bootstrap.get("mode") != "enrollment":
        raise ValueError("Configuration-only package; generate an enrollment package on the real server")
    if bootstrap.get("os") != "linux" or config.get("os") != "linux":
        raise ValueError("This is not a Linux agent package")
    if any(bootstrap.get(k) != config.get(k) for k in ["actor_id", "hostname", "api_url"]):
        raise ValueError("Package identity mismatch")
    if config["hostname"].casefold() not in {name.casefold() for name in names if name}:
        raise ValueError("Package belongs to a different Linux host")
    if not bootstrap.get("enrollment_token") or bootstrap.get("expires_at", 0) <= now:
        raise ValueError("Enrollment expired; generate a fresh package")
    if not config["api_url"].startswith("https://"):
        raise ValueError("Linux enrollment requires HTTPS")


def configure(bundle: Path):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Linux root installation is required")
    bootstrap = json.loads((bundle / "bootstrap.json").read_text())
    config = json.loads((bundle / "agent.json").read_text())
    validate_bundle(bootstrap, config, {platform.node(), socket.getfqdn()}, time.time())
    for field in ["state_root", "work_root", "public_key_file"]:
        protected(Path(config[field]))
    config["os_version"] = platform.platform()[:128]
    for profile in config["profiles"]:
        profile["validated"] = False
    enroll(
        config["api_url"],
        bootstrap["enrollment_token"],
        config["hostname"],
        config["os_version"],
        Path(config["credential_file"]),
        expected_actor_id=config["actor_id"],
        platform_name="linux",
    )
    write_json(Path(config["config_file"]), config, 0o644)
    bootstrap["enrollment_token"] = None
    # Clear the consumed token in the extracted copy. The archived token is already single-use.
    (bundle / "bootstrap.json").write_text(json.dumps(bootstrap, indent=2))
    print("Enrolled Linux actor:", config["actor_id"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    configure(parser.parse_args().bundle)
