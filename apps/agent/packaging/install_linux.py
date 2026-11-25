"""Standard-library installer for an actor-specific Linux ZIP. Installs a stopped service."""

import argparse
import hashlib
import json
import os
import platform
import socket
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from urllib.request import HTTPRedirectHandler, HTTPSHandler, build_opener

ROOT = Path("/opt/atomic-control")
STATE = Path("/var/lib/atomic-control")
CONFIG = Path("/etc/atomic-control")
UNIT = Path("/etc/systemd/system/atomic-control-agent.service")


def check_path(path):
    for part in [*reversed(path.parents), path]:
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError(
                    "Installation paths must be root-owned without symlinks or group/other writes"
                )


def validate_files(bundle: Path, manifest: dict):
    for name, expected in manifest["files"].items():
        parts = PurePosixPath(name)
        if parts.is_absolute() or ".." in parts.parts or "\\" in name:
            raise ValueError("Invalid package path")
        source = bundle / name
        if any((bundle / Path(*parts.parts[:i])).is_symlink() for i in range(1, len(parts.parts) + 1)):
            raise ValueError("Package links are not permitted")
        if not source.is_file() or source.stat().st_size > 2_000_000:
            raise ValueError("Invalid package file")
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError("Package checksum mismatch: " + name)


def validate_resume(root: Path, state: Path, config: Path, unit: Path):
    """Allow only the empty, unenrolled state left by a failed first installation."""
    for path in [root, state, config, unit]:
        check_path(path)
    enabled = unit.parent / "multi-user.target.wants" / unit.name
    if unit.exists() or enabled.exists() or enabled.is_symlink():
        raise ValueError("A service already exists; resume cannot replace an installed agent")
    if config.exists() and (not config.is_dir() or any(config.iterdir())):
        raise ValueError("Configuration already exists; preserve it and use the maintenance procedure")
    if state.exists():
        if not state.is_dir():
            raise ValueError("Invalid existing agent state")
        for entry in state.iterdir():
            check_path(entry)
            if entry.name not in {"jobs", "work", "secrets"} or not entry.is_dir() or any(entry.iterdir()):
                raise ValueError("Credentials or job state exist; resume will not alter them")
    if not root.is_dir() or {entry.name for entry in root.iterdir()} - {
        "runtime",
        "venv",
        "job-signing-public.pem",
        "atomic-red-team",
    }:
        raise ValueError("Expected only the partial first-installation runtime")
    catalog = root / "atomic-red-team"
    if catalog.exists() or catalog.is_symlink():
        check_path(catalog)
        if catalog.is_symlink() or not catalog.is_dir() or any(catalog.iterdir()):
            raise ValueError(
                "Resume requires an empty catalog placeholder; preserve existing catalog content"
            )
    for path in [root / "venv", root / "venv/bin", root / "venv/pyvenv.cfg"]:
        check_path(path)
    python = root / "venv/bin/python"
    if not python.is_file() or not (root / "venv/pyvenv.cfg").is_file():
        raise ValueError("The partial installation has no usable virtual environment")
    check_path(python.resolve(strict=True))


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_server(api_url: str):
    if not api_url.startswith("https://"):
        raise ValueError("Enrollment requires HTTPS")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirects())
    with opener.open(api_url.rstrip("/") + "/health", timeout=15) as response:
        data = response.read(4097)
        if len(data) > 4096 or response.status != 200 or json.loads(data).get("mode") != "real":
            raise ValueError("The enrollment server must be a verified real-mode API")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument(
        "--resume-enrollment", action="store_true", help="Resume only an empty, unenrolled first installation"
    )
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or sys.version_info < (3, 12):
        raise SystemExit("Run with sudo and Python 3.12+ on Linux")
    import fcntl

    lock = os.open("/run/atomic-control-installer.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another agent installer is running") from None
        install(args)
    finally:
        os.close(lock)


def install(args):
    if not Path("/run/systemd/system").is_dir():
        raise SystemExit("A running systemd system manager is required")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise SystemExit("A unified cgroup v2 system is required")
    bundle = Path(__file__).resolve().parent
    manifest = json.loads((bundle / "manifest.json").read_text())
    bootstrap = json.loads((bundle / "bootstrap.json").read_text())
    config = json.loads((bundle / "agent.json").read_text())
    if manifest.get("os") != "linux" or config.get("os") != "linux" or bootstrap.get("os") != "linux":
        raise SystemExit("Linux package required")
    if bootstrap.get("mode") != "enrollment" or not bootstrap.get("enrollment_token"):
        raise SystemExit("Configuration-only package; generate a real enrollment package")
    if bootstrap.get("expires_at", 0) <= time.time():
        raise SystemExit("Enrollment token expired; generate a fresh package")
    if bootstrap["hostname"].casefold() not in {platform.node().casefold(), socket.getfqdn().casefold()}:
        raise SystemExit("This package belongs to a different host")
    if any(
        bootstrap.get(k) != config.get(k) or manifest.get(k) != config.get(k)
        for k in ["hostname", "actor_id", "os"]
    ):
        raise SystemExit("Package identity mismatch")
    validate_files(bundle, manifest)
    for path in [ROOT, STATE, CONFIG, UNIT]:
        check_path(path)
    if args.resume_enrollment:
        validate_resume(ROOT, STATE, CONFIG, UNIT)
    elif ROOT.exists() or CONFIG.exists() or UNIT.exists() or STATE.exists():
        raise SystemExit(
            "An installation or unreconciled job already exists. Follow the upgrade/reconciliation guide"
        )
    for executable in ["/usr/bin/systemd-run", "/usr/bin/systemctl", "/bin/bash", "/bin/sh"] + (
        [] if config.get("delivery_mode") == "on_demand" else ["/usr/bin/git"]
    ):
        if not Path(executable).is_file():
            raise SystemExit("Required tool missing: " + executable)
    version = (
        subprocess.check_output(["/usr/bin/systemd-run", "--version"], text=True).splitlines()[0].split()
    )
    if len(version) < 2 or not version[1].isdigit() or int(version[1]) < 245:
        raise SystemExit("systemd 245+ is required")
    # Reject altered fixed paths rather than installing configuration that points outside protected directories.
    expected = {
        "state_root": str(STATE / "jobs"),
        "work_root": str(STATE / "work"),
        "config_file": str(CONFIG / "agent.json"),
        "credential_file": str(STATE / "secrets/credential.json"),
        "public_key_file": str(ROOT / "job-signing-public.pem"),
        "catalog_root": str(ROOT / "atomic-red-team"),
        "python_path": str(ROOT / "venv/bin/python"),
    }
    if any(config.get(k) != v for k, v in expected.items()):
        raise SystemExit("Package installation path mismatch")
    verify_server(config["api_url"])
    if args.check_only:
        print(
            "Linux package and verified HTTPS checks passed. No files installed and no enrollment performed"
        )
        return
    os.umask(0o022)
    for directory, mode in [
        (ROOT, 0o755),
        (CONFIG, 0o755),
        (STATE, 0o755),
        (STATE / "jobs", 0o755),
        (STATE / "work", 0o755),
        (STATE / "secrets", 0o700),
    ]:
        directory.mkdir(mode=mode, parents=True, exist_ok=True)
        directory.chmod(mode)
    if config.get("delivery_mode") != "on_demand":
        (ROOT / "atomic-red-team").mkdir(mode=0o755, exist_ok=True)
    # Copy only manifest-verified source files. Ignore any extra files in the extracted directory.
    for name in manifest["files"]:
        if name.startswith("runtime/") or name == "job-signing-public.pem":
            target = ROOT / name
            check_path(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((bundle / name).read_bytes())
            target.chmod(0o644)
    if not args.resume_enrollment:
        subprocess.run([sys.executable, "-I", "-m", "venv", str(ROOT / "venv")], check=True)
    python = str(ROOT / "venv/bin/python")
    subprocess.run(
        [python, "-I", "-m", "pip", "install", "-r", str(ROOT / "runtime/requirements.txt")], check=True
    )
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
            str(ROOT / "runtime"),
        ],
        check=True,
    )
    subprocess.run([python, "-I", "-m", "apps.agent.linux.bootstrap", "--bundle", str(bundle)], check=True)
    UNIT.write_bytes((bundle / "atomic-control-agent.service").read_bytes())
    UNIT.chmod(0o644)
    subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
    print("Agent enrolled; service remains disabled and stopped. No Atomic test has run.")
    print(
        "On-demand delivery downloads one approved bundle per attempt."
        if config.get("delivery_mode") == "on_demand"
        else "An empty protected catalog directory allows connectivity; it is not a reviewed Atomic checkout."
    )
    print("To connect this enrolled agent: sudo systemctl enable --now atomic-control-agent")
    print("Check startup: sudo systemctl status atomic-control-agent --no-pager -l")
    print("If startup fails: sudo journalctl -u atomic-control-agent -b -n 60 --no-pager")
    print(
        f"If sudo cannot resolve host {config['hostname']}, use sudoedit /etc/hosts and include {config['hostname']} in the 127.0.1.1 entry; keep localhost entries."
    )
    print(
        "Before requesting tests: prepare and approve test bundles and confirm registered profiles are healthy."
        if config.get("delivery_mode") == "on_demand"
        else "Before requesting tests: provision the exact reviewed pinned catalog and confirm registered profiles are healthy."
    )


if __name__ == "__main__":
    main()
