"""Idle, signed installation of one exact official Atomic Git commit; never runs tests."""

import json
import os
import shutil
import stat
import subprocess
import threading
from pathlib import Path
from uuid import UUID

from apps.api.app.catalog.parser import parse_file
from apps.api.app.services.common import redact

from ..catalog_config import REMOTE, fingerprint, verify_manifest
from ..job_client import heartbeat_payload
from ..logging import event
from .security import protected, protected_tree, write_json


class CatalogFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def journal_path(config):
    return Path(config["state_root"]).parent / "catalog-install.json"


def git_environment():
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_PROTOCOL_FROM_USER": "0",
    }
    if os.environ.get("SSL_CERT_FILE"):
        env["GIT_SSL_CAINFO"] = os.environ["SSL_CERT_FILE"]
    return env


def git(root, *arguments, timeout=30, error="verification_failed"):
    command = [
        "/usr/bin/git",
        "--no-optional-locks",
        "-c",
        "safe.directory=" + str(root),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.followRedirects=false",
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "pack.threads=1",
        "-C",
        str(root),
        *arguments,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=timeout, env=git_environment()
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "stderr", "") or ""
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        event("catalog.git_failed", error=error, detail=redact(detail, 2048)[0])
        raise CatalogFailure(error) from None


def verify_checkout(root, value):
    protected_tree(root)
    if not (root / ".git").is_dir() or (root / ".git").is_symlink():
        raise CatalogFailure("verification_failed")
    if git(root, "rev-parse", "HEAD") != value["revision"] or git(
        root, "status", "--porcelain", "--untracked-files=all", "--ignored"
    ):
        raise CatalogFailure("verification_failed")
    definitions = {}
    for technique in {test["technique"] for test in value["tests"]}:
        definitions.update(
            {
                item["auto_generated_guid"]: item
                for item in parse_file(root / "atomics" / technique / (technique + ".yaml"))
            }
        )
    for test in value["tests"]:
        if test["guid"] not in definitions or fingerprint(definitions[test["guid"]]) != test["sha256"]:
            event("catalog.definition_mismatch", guid=test["guid"], technique=test["technique"])
            raise CatalogFailure("verification_failed")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def normalize_tree(root):
    # The service umask is 0077. Make this verified source readable to execution profiles.
    folders = []
    total = 0

    def fail_walk(error):
        raise error

    for folder, directories, files in os.walk(root, followlinks=False, onerror=fail_walk):
        directory = Path(folder)
        folders.append(directory)
        for entry in [
            directory,
            *(directory / name for name in directories),
            *(directory / name for name in files),
        ]:
            info = entry.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise CatalogFailure("verification_failed")
            os.chown(entry, 0, 0, follow_symlinks=False)
            entry.chmod(0o755 if entry.is_dir() or info.st_mode & 0o111 else 0o644)
        for name in files:
            path = directory / name
            total += path.stat().st_size
            if total > 1_000_000_000:
                raise CatalogFailure("verification_failed")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    for folder in reversed(folders):
        sync_directory(folder)


def fetch(root, revision):
    root.mkdir(mode=0o700)
    git(root, "init", "--quiet", "--template=", error="fetch_failed")
    git(
        root,
        "fetch",
        "--quiet",
        "--depth=1",
        "--no-tags",
        "--no-recurse-submodules",
        REMOTE,
        revision,
        timeout=300,
        error="fetch_failed",
    )
    git(root, "checkout", "--quiet", "--detach", "--force", "FETCH_HEAD", timeout=120, error="fetch_failed")
    normalize_tree(root)


def locations(config, deployment_id):
    uid = str(UUID(deployment_id))
    root = Path(config["catalog_root"])
    if root.name != "atomic-red-team" or root.parent != Path(config["public_key_file"]).parent:
        raise ValueError("Unsupported catalog installation path")
    protected(root.parent)
    return root, root.parent / (".catalog-stage-" + uid), root.parent / ("catalog-before-" + uid)


def receipt(config, config_file, claims, status, error=""):
    result = {
        "generation": claims["generation"],
        "payload_hash": claims["payload_hash"],
        "status": status,
        "observed_revision": claims["payload"]["revision"] if status == "applied" else "",
        "error": error,
    }
    config.update(
        catalog_sync_generation=claims["generation"],
        catalog_sync_hash=claims["payload_hash"],
        catalog_sync_receipt={"id": claims["jti"], "result": result},
    )
    if status == "applied":
        config["revision"] = claims["payload"]["revision"]
    write_json(config_file, config, 0o644)
    return config


def clear_journal(path):
    path.unlink()
    sync_directory(path.parent)


def recover(config_file, error="interrupted"):
    config = json.loads(config_file.read_text())
    path = journal_path(config)
    if not path.exists() and not path.is_symlink():
        return config
    protected(path, private=True)
    record = json.loads(path.read_text())
    claims = record["claims"]
    if (
        claims["payload"]["actor_id"] != config["actor_id"]
        or record["catalog_root"] != config["catalog_root"]
    ):
        raise RuntimeError("Catalog journal identity changed; administrator reconciliation required")
    root, stage, backup = locations(config, claims["jti"])
    saved = config.get("catalog_sync_receipt", {})
    if saved.get("id") == claims["jti"] and saved.get("result", {}).get("status") == "applied":
        verify_checkout(root, claims["payload"])
        clear_journal(path)
        return config
    if backup.exists() or backup.is_symlink():
        protected(backup)
        if root.exists() or root.is_symlink():
            protected(root)
            quarantine = root.parent / ("catalog-interrupted-" + str(UUID(claims["jti"])))
            if quarantine.exists() or quarantine.is_symlink():
                raise RuntimeError("Catalog recovery path already exists; reconciliation required")
            root.rename(quarantine)
            quarantine.chmod(0o700)
        backup.rename(root)
        root.chmod(record["old_mode"])
        sync_directory(root.parent)
    elif record["phase"] != "preparing" and (not root.exists() or not stage.exists()):
        raise RuntimeError("Cannot establish prior catalog state; reconciliation required")
    config["revision"] = record["old_revision"]
    config = receipt(config, config_file, claims, "failed", error)
    clear_journal(path)
    return config


def apply_manifest(config, config_file, token):
    protected(config_file)
    protected(Path(config["public_key_file"]))
    claims = verify_manifest(token, config, Path(config["public_key_file"]).read_text())
    active = Path(config["state_root"]) / "active.json"
    if (
        active.exists()
        or active.is_symlink()
        or journal_path(config).exists()
        or journal_path(config).is_symlink()
    ):
        raise RuntimeError("Unreconciled work prevents catalog installation")
    if json.loads(config_file.read_text()) != config:
        raise RuntimeError("Local configuration changed; restart before installing a catalog")
    if config.get("catalog_sync_generation") == claims["generation"]:
        saved = config["catalog_sync_receipt"]
        if saved["id"] != claims["jti"]:
            raise ValueError("Catalog receipt identity differs")
        if saved["result"]["status"] == "applied":
            verify_checkout(Path(config["catalog_root"]), claims["payload"])
        return config, saved
    path = journal_path(config)
    try:
        root, stage, backup = locations(config, claims["jti"])
        if not root.exists() and not root.is_symlink():
            root.mkdir(mode=0o755)
            root.chmod(0o755)
        protected(root)
        if not root.is_dir():
            raise CatalogFailure("apply_failed")
        if stage.exists() or stage.is_symlink() or backup.exists() or backup.is_symlink():
            raise CatalogFailure("apply_failed")
        # A matching clean checkout needs verification only; no network or replacement.
        try:
            verify_checkout(root, claims["payload"])
        except (CatalogFailure, OSError, ValueError, KeyError):
            pass
        else:
            config = receipt(config, config_file, claims, "applied")
            return config, config["catalog_sync_receipt"]
        if shutil.disk_usage(root.parent).free < 1_000_000_000:
            raise CatalogFailure("insufficient_space")
        record = {
            "claims": claims,
            "catalog_root": str(root),
            "phase": "preparing",
            "old_revision": config["revision"],
            "old_mode": stat.S_IMODE(root.stat().st_mode),
        }
        write_json(path, record, exclusive=True)
        event("catalog.fetching", revision=claims["payload"]["revision"])
        fetch(stage, claims["payload"]["revision"])
        event("catalog.verifying", revision=claims["payload"]["revision"])
        verify_checkout(stage, claims["payload"])
        if json.loads(config_file.read_text()) != config:
            raise CatalogFailure("configuration_changed")
        record["phase"] = "switching"
        write_json(path, record)
        root.rename(backup)
        backup.chmod(0o700)
        sync_directory(root.parent)
        stage.rename(root)
        sync_directory(root.parent)
        record["phase"] = "installed"
        write_json(path, record)
        verify_checkout(root, claims["payload"])
        config = receipt(config, config_file, claims, "applied")
        clear_journal(path)
        event("catalog.applied", revision=claims["payload"]["revision"])
    except (CatalogFailure, OSError, ValueError, KeyError) as exc:
        code = exc.code if isinstance(exc, CatalogFailure) else "apply_failed"
        event("catalog.install_failed", error=code, revision=claims["payload"]["revision"])
        if path.exists():
            config = recover(config_file, code)
        else:
            config = receipt(json.loads(config_file.read_text()), config_file, claims, "failed", code)
    return config, config["catalog_sync_receipt"]


def readiness(config):
    saved = config.get("catalog_sync_receipt", {})
    if saved.get("result", {}).get("status") != "applied" or not config.get("revision"):
        return "missing", "", ""
    try:
        root = Path(config["catalog_root"])
        protected(root)
        if not (root / ".git").is_dir() or (root / ".git").is_symlink():
            return "missing", "", ""
        if git(root, "rev-parse", "HEAD") != config["revision"]:
            return "mismatch", "", ""
        if git(root, "status", "--porcelain", "--untracked-files=all", "--ignored"):
            return "dirty", "", ""
        return "ready", config["revision"], saved["result"]["payload_hash"]
    except (OSError, ValueError, KeyError, CatalogFailure):
        return "unavailable", "", ""


def synchronize(config, config_file, client):
    answer = client.post("agents/catalog-install/poll")
    if not answer.get("manifest"):
        return config
    stop = threading.Event()

    def keep_alive():
        while not stop.wait(15):
            try:
                client.post("agents/heartbeat", heartbeat_payload(config))
            except Exception:
                pass

    thread = threading.Thread(target=keep_alive, daemon=True)
    thread.start()
    try:
        updated, saved = apply_manifest(config, config_file, answer["manifest"])
    finally:
        stop.set()
        thread.join(timeout=21)
    client.post(f"agents/catalog-install/{saved['id']}/result", saved["result"])
    client.post("agents/heartbeat", heartbeat_payload(updated))
    return updated
