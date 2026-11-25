"""One-time, stopped-service runtime update. Review this file and the ZIP checksum first."""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from uuid import uuid4

ROOT = Path("/opt/atomic-control")
STATE = Path("/var/lib/atomic-control")
CONFIG = Path("/etc/atomic-control/agent.json")


def protected(path):
    for entry in [*reversed(path.parents), path]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Update paths must be root-owned without links or group/other writes")


def validate(bundle, current, manifest=None):
    manifest = manifest or json.loads((bundle / "manifest.json").read_text())
    for name, expected in manifest["files"].items():
        parts = PurePosixPath(name)
        if parts.is_absolute() or ".." in parts.parts or "\\" in name:
            raise ValueError("Invalid package path")
        source = bundle / name
        if any((bundle / Path(*parts.parts[:i])).is_symlink() for i in range(1, len(parts.parts) + 1)):
            raise ValueError("Package links are not permitted")
        if (
            not source.is_file()
            or source.stat().st_size > 2_000_000
            or hashlib.sha256(source.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("Package checksum mismatch")
    bootstrap = json.loads((bundle / "bootstrap.json").read_text())
    included = json.loads((bundle / "agent.json").read_text())
    if (
        manifest.get("mode") != "configuration_only"
        or bootstrap.get("mode") != "configuration_only"
        or bootstrap.get("enrollment_token")
    ):
        raise ValueError("Use a configuration-only package; this updater never reenrolls")
    for field in ("actor_id", "hostname", "os"):
        if any(value.get(field) != current.get(field) for value in (manifest, bootstrap, included)):
            raise ValueError("Package belongs to a different actor")
    if (
        current.get("os") != "linux"
        or included.get("api_url") != current.get("api_url")
        or bootstrap.get("api_url") != current.get("api_url")
    ):
        raise ValueError("Update cannot change the platform or API address")
    key = ROOT / "job-signing-public.pem"
    protected(key)
    if key.read_bytes().strip() != (bundle / "job-signing-public.pem").read_bytes().strip():
        raise ValueError("Update cannot replace the pinned signing key")
    fixed = {
        "config_file": str(CONFIG),
        "credential_file": str(STATE / "secrets/credential.json"),
        "state_root": str(STATE / "jobs"),
        "work_root": str(STATE / "work"),
        "catalog_root": str(ROOT / "atomic-red-team"),
        "public_key_file": str(key),
        "python_path": str(ROOT / "venv/bin/python"),
    }
    if any(current.get(k) != v for k, v in fixed.items()):
        raise ValueError("Existing agent paths differ from the supported installation")
    for path in [
        ROOT,
        STATE,
        STATE / "jobs",
        CONFIG,
        Path(current["credential_file"]),
        Path(current["python_path"]).resolve(strict=True),
    ]:
        protected(path)
    if Path(current["credential_file"]).stat().st_mode & 0o077:
        raise ValueError("Existing credential must remain root-private")
    for journal in [STATE / "jobs/active.json", STATE / "catalog-install.json"]:
        if journal.exists() or journal.is_symlink():
            raise ValueError("Unreconciled job/catalog installation exists; reconcile before updating")
    required = {
        "agent.json",
        "bootstrap.json",
        "job-signing-public.pem",
        "runtime/pyproject.toml",
        "runtime/requirements.txt",
        "runtime/apps/agent/linux/profile_sync.py",
        "runtime/apps/agent/profile_config.py",
        "runtime/apps/agent/catalog_config.py",
        "runtime/apps/agent/linux/catalog_sync.py",
    }
    if required - manifest["files"].keys():
        raise ValueError("Update package is incomplete")
    return manifest


def update(bundle, enable, check_only=False, enable_catalog=False, enable_on_demand=False):
    protected(CONFIG)
    current = json.loads(CONFIG.read_text())
    python = str(ROOT / "venv/bin/python")
    protected(Path(python).parent)
    protected(ROOT / "venv/pyvenv.cfg")
    protected(Path(python).resolve(strict=True))
    protected(ROOT / "job-signing-public.pem")
    manifest_bytes = (bundle / "manifest.json").read_bytes()
    # Authenticate the manifest using the EXISTING key and runtime, before pip or copying code.
    subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import jwt,sys; from pathlib import Path; b=Path(sys.argv[1]); c=jwt.decode((b/'manifest.jwt').read_text(),Path(sys.argv[2]).read_text(),algorithms=['RS256'],issuer='atomic-control-package',audience=sys.argv[3],options={'require':['exp','iat','type','manifest_sha256']}); assert c['type']=='linux-runtime-package-v1'; assert c['manifest_sha256']==sys.argv[4]",
            str(bundle),
            str(ROOT / "job-signing-public.pem"),
            current["actor_id"],
            hashlib.sha256(manifest_bytes).hexdigest(),
        ],
        check=True,
    )
    manifest = validate(bundle, current, json.loads(manifest_bytes))
    state = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "atomic-control-agent"], capture_output=True, text=True
    )
    if state.stdout.strip() not in {"inactive", "failed"}:
        raise ValueError("Stop atomic-control-agent before updating")
    if check_only:
        print("Update checks passed; no files changed and no enrollment performed")
        return
    credential = Path(current["credential_file"])
    credential_hash = hashlib.sha256(credential.read_bytes()).hexdigest()
    catalog = ROOT / "atomic-red-team"
    if not catalog.exists() and not catalog.is_symlink():
        catalog.mkdir(mode=0o755)
        catalog.chmod(0o755)
    protected(catalog)
    stage = ROOT / ("runtime-update-" + uuid4().hex)
    stage.mkdir(mode=0o755)
    for name in manifest["files"]:
        if name.startswith("runtime/"):
            target = stage / name.removeprefix("runtime/")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            content = (bundle / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != manifest["files"][name]:
                raise ValueError("Package changed during update")
            target.write_bytes(content)
            target.chmod(0o644)
    python = str(ROOT / "venv/bin/python")
    subprocess.run([python, "-I", "-m", "pip", "install", "-r", str(stage / "requirements.txt")], check=True)
    subprocess.run(
        [
            python,
            "-I",
            "-m",
            "pip",
            "install",
            "--force-reinstall",
            "--no-deps",
            "--no-build-isolation",
            str(stage),
        ],
        check=True,
    )
    subprocess.run(
        [
            python,
            "-I",
            "-c",
            "from apps.agent.linux.profile_sync import synchronize; from apps.agent.linux.catalog_sync import synchronize as catalog_sync",
        ],
        check=True,
    )
    runtime = ROOT / "runtime"
    protected(runtime)
    runtime.rename(ROOT / ("runtime-before-update-" + uuid4().hex))
    stage.rename(runtime)
    changes: dict[str, str | bool] = {}
    if enable:
        changes["profile_sync_enabled"] = True
    if enable_catalog:
        changes["catalog_sync_enabled"] = True
    if enable_on_demand:
        changes.update(delivery_mode="on_demand", catalog_sync_enabled=False)
    if changes:
        before = CONFIG.parent / ("agent.before-runtime-update-" + uuid4().hex + ".json")
        fd = os.open(before, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(CONFIG.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        # Use the now-installed protected writer; never copy the ZIP's agent.json.
        subprocess.run(
            [
                python,
                "-I",
                "-c",
                "import json,sys; from pathlib import Path; from apps.agent.linux.security import write_json; p=Path(sys.argv[1]); c=json.loads(p.read_text()); c.update(json.loads(sys.argv[2])); write_json(p,c,0o644)",
                str(CONFIG),
                json.dumps(changes),
            ],
            check=True,
        )
    if hashlib.sha256(credential.read_bytes()).hexdigest() != credential_hash:
        raise RuntimeError("Credential changed unexpectedly; leave the service stopped")
    print("Runtime updated; credentials, signing key and pinned catalog preserved. Service remains stopped.")
    print(
        "Start atomic-control-agent, then watch Actors → Execution profiles for signed synchronization results."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-profile-sync", action="store_true")
    parser.add_argument("--enable-catalog-sync", action="store_true")
    parser.add_argument("--enable-on-demand", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or sys.version_info < (3, 12):
        raise SystemExit("Run with sudo and Python 3.12+ on Linux")
    os.umask(0o022)
    import fcntl

    protected(STATE)
    descriptors = []
    try:
        for path in [Path("/run/atomic-control-installer.lock"), STATE / "agent.lock"]:
            if path.exists() or path.is_symlink():
                protected(path)
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            descriptors.append(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SystemExit("An agent, identity probe or installer is running; stop it first") from None
        update(
            Path(__file__).resolve().parent,
            args.enable_profile_sync,
            args.check_only,
            args.enable_catalog_sync,
            args.enable_on_demand,
        )
    finally:
        for fd in descriptors:
            os.close(fd)


if __name__ == "__main__":
    main()
