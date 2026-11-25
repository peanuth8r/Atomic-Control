"""Apply signed profile metadata while idle; preserve transport and catalog state."""

import json
import threading
from pathlib import Path
from uuid import uuid4

from ..job_client import heartbeat_payload
from ..profile_config import fingerprint, payload, verify_manifest
from .broker import validate_profiles
from .security import protected, write_json


def apply_manifest(config: dict, config_file: Path, token: str) -> tuple[dict, dict]:
    protected(config_file)
    protected(Path(config["public_key_file"]))
    claims = verify_manifest(token, config, Path(config["public_key_file"]).read_text())
    journal = Path(config["state_root"]) / "active.json"
    if journal.exists() or journal.is_symlink():
        raise RuntimeError("Unreconciled execution prevents profile synchronization")
    current = json.loads(config_file.read_text())
    if current != config:
        raise RuntimeError("Local configuration changed; restart before synchronization")
    response = {
        "generation": claims["generation"],
        "payload_hash": claims["payload_hash"],
        "results": {},
        "error": "",
    }
    try:
        if config.get("profile_sync_generation") == claims["generation"]:
            if fingerprint(payload(config)) != claims["payload_hash"]:
                raise ValueError("Applied profile metadata changed")
            response["results"] = config["profile_validation_results"]
        else:
            backup = config_file.parent / ("agent.before-profile-sync-" + uuid4().hex + ".json")
            write_json(backup, current, exclusive=True)
            current.update(
                profiles=[{**p, "validated": False} for p in claims["payload"]["profiles"]],
                profile_sync_generation=claims["generation"],
                profile_sync_hash=claims["payload_hash"],
            )
            current.pop("profile_validation_results", None)
            write_json(config_file, current, 0o644)
            response["results"] = validate_profiles(current, config_file)
    except (OSError, ValueError, KeyError, RuntimeError):
        response["error"] = "apply_failed"
        current = json.loads(config_file.read_text())
    return current, {"id": claims["jti"], "result": response}


def synchronize(config: dict, config_file: Path, client) -> dict:
    answer = client.post("agents/profile-sync/poll")
    if not answer.get("manifest"):
        return config
    stop = threading.Event()

    def keep_alive():
        while not stop.wait(15):
            try:
                client.post("agents/heartbeat", heartbeat_payload(config))
            except Exception:
                pass  # Delivery is retried; the server still prevents job claims.

    thread = threading.Thread(target=keep_alive, daemon=True)
    thread.start()
    try:
        updated, receipt = apply_manifest(config, config_file, answer["manifest"])
    finally:
        stop.set()
        thread.join(timeout=21)
    # Reload on every loop too: a lost acknowledgement must not replay the apply/probes.
    client.post(f"agents/profile-sync/{receipt['id']}/result", receipt["result"])
    client.post("agents/heartbeat", heartbeat_payload(updated))
    return updated
