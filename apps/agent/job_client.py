import os
import ssl
import sys
from typing import Any

import httpx


def tls_verification() -> ssl.SSLContext | bool:
    if sys.platform in {"linux", "win32"}:
        # Use native trust: Linux CA paths or Windows CA/ROOT certificate stores.
        return ssl.create_default_context(
            cafile=os.environ.get("SSL_CERT_FILE"), capath=os.environ.get("SSL_CERT_DIR")
        )
    return True


class JobClient:
    def __init__(self, base_url: str, credential: str):
        if not base_url.startswith("https://"):
            raise ValueError("Agent transport requires HTTPS")
        self.http = httpx.Client(
            base_url=base_url.rstrip("/") + "/api/v1/",
            headers={"Authorization": "Bearer " + credential},
            timeout=20,
            follow_redirects=False,
            verify=tls_verification(),
        )

    def post(self, path: str, payload: dict[str, Any] | None = None):
        response = self.http.post(path, json=payload or {})
        response.raise_for_status()
        return response.json()

    def download_artifact(self, job, destination, tick):
        from .artifacts import MAX_BYTES

        for attempt in range(3):
            try:
                size = 0
                with self.http.stream(
                    "GET",
                    f"agents/jobs/{job['run_id']}/artifact",
                    headers={"X-Job-Grant": job["download_grant"]},
                ) as response:
                    response.raise_for_status()
                    with destination.open("xb") as file:
                        for chunk in response.iter_bytes(65536):
                            tick()
                            size += len(chunk)
                            if size > min(MAX_BYTES, job["snapshot"]["artifact"]["size"]):
                                raise ValueError("Artifact download exceeds signed size")
                            file.write(chunk)
                if size != job["snapshot"]["artifact"]["size"]:
                    raise ValueError("Incomplete artifact download")
                return
            except (httpx.TransportError, httpx.HTTPStatusError):
                destination.unlink(missing_ok=True)
                tick()
                if attempt == 2:
                    raise
                import time

                time.sleep(attempt + 1)

    def close(self):
        self.http.close()


def heartbeat_payload(config: dict, active_execution_id: str | None = None) -> dict:
    result = {
        "hostname": config["hostname"],
        "os": config.get("os", "windows"),
        "os_version": config["os_version"],
        "agent_version": "0.2.0",
        "delivery_mode": config.get("delivery_mode", "checkout"),
        "artifact_protocol": 1 if config.get("delivery_mode") == "on_demand" else 0,
        "revision": config["revision"],
        "profiles": {p["id"]: bool(p.get("validated", False)) for p in config["profiles"]},
        "health": "healthy",
        "active_execution_id": active_execution_id,
    }
    if config.get("os", "windows") in {"linux", "windows"} and config.get("profile_sync_enabled"):
        from .profile_config import applied_hash

        result.update(profile_sync_protocol=1, profile_config_hash=applied_hash(config))
    if config.get("delivery_mode") == "on_demand":
        from pathlib import Path

        state = Path(config["state_root"])
        downloads = state / "downloads"
        residue = not (state / "active.json").exists() and downloads.exists() and any(downloads.iterdir())
        result["workspace_residue"] = bool(residue)
        if residue:
            result["health"] = "degraded"
        result["revision"] = ""
        return result
    if config.get("os", "windows") == "windows" and config.get("catalog_verification_enabled"):
        from .windows_catalog import reported_revision

        result["revision"] = reported_revision(config)
    if config.get("os") == "linux" and config.get("catalog_sync_enabled"):
        from .linux.catalog_sync import readiness

        health, revision, hashed = readiness(config)
        result.update(
            catalog_sync_protocol=1, catalog_health=health, revision=revision, catalog_config_hash=hashed
        )
    return result
