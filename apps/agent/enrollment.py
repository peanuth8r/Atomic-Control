import json
import os
import sys
from pathlib import Path

import httpx

from .job_client import tls_verification


def enroll(
    base_url: str,
    token: str,
    hostname: str,
    os_version: str,
    destination: Path,
    expected_actor_id: str | None = None,
    platform_name: str = "windows",
):
    if (
        platform_name not in {"windows", "linux"}
        or (platform_name == "windows" and os.name != "nt")
        or (platform_name == "linux" and sys.platform != "linux")
        or not base_url.startswith("https://")
    ):
        raise RuntimeError("Enrollment requires Windows/Linux and HTTPS")
    response = (
        httpx.post(
            base_url.rstrip("/") + "/api/v1/agents/enroll",
            json={
                "token": token,
                "hostname": hostname,
                "agent_version": "0.2.0",
                "os_version": os_version,
                "os": platform_name,
            },
            timeout=20,
            verify=tls_verification(),
        )
        .raise_for_status()
        .json()
    )
    if expected_actor_id is not None and response.get("actor_id") != expected_actor_id:
        raise RuntimeError("Enrollment returned a different actor identity")
    save_credential(destination, response)
    return response["actor_id"]


def save_credential(destination: Path, value: dict):
    if sys.platform == "linux":
        from .linux.security import save_credential as linux_save

        return linux_save(destination, value)
    import win32crypt

    from .execution_broker import restrict_acl

    destination.parent.mkdir(parents=True, exist_ok=True)
    restrict_acl(destination.parent)

    # LocalMachine DPAPI + SYSTEM-only ACL on the containing directory.
    encrypted = win32crypt.CryptProtectData(
        json.dumps(value).encode(), "AtomicControlAgent", None, None, None, 4
    )
    temp = destination.with_suffix(".tmp")
    temp.write_bytes(encrypted)
    temp.replace(destination)


def load_credential(destination: Path):
    if sys.platform == "linux":
        from .linux.security import load_credential as linux_load

        return linux_load(destination)
    import win32crypt

    return json.loads(win32crypt.CryptUnprotectData(destination.read_bytes(), None, None, None, 0)[1])
