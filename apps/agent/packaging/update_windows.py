"""Stopped-service, signed runtime update. Preserves actor credentials, profiles and signing key."""

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path, PurePosixPath, PureWindowsPath
from uuid import uuid4

import jwt


def require_machine_python(executable):
    candidate = PureWindowsPath(executable)
    roots = [
        PureWindowsPath(value)
        for key in ("USERPROFILE", "LOCALAPPDATA", "APPDATA")
        if (value := os.environ.get(key))
    ]
    roots.append(PureWindowsPath(os.environ.get("SystemDrive", "C:") + "\\") / "Users")
    try:
        import winreg

        with winreg.OpenKey(  # type: ignore[attr-defined]
            winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined]
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        ) as key:
            roots.append(
                PureWindowsPath(os.path.expandvars(winreg.QueryValueEx(key, "ProfilesDirectory")[0]))  # type: ignore[attr-defined]
            )
    except (ImportError, OSError):
        pass
    if (
        not candidate.is_absolute()
        or candidate.suffix.lower() != ".exe"
        or any(part.lower() in {"appdata", "windowsapps"} for part in candidate.parts)
        or any(root == candidate or root in candidate.parents for root in roots if root.is_absolute())
    ):
        raise ValueError(
            "Use an all-users Python executable outside user profiles/AppData/WindowsApps; do not relocate credentials or reenroll"
        )


def update(bundle, enable_on_demand=False, check_only=False):
    import ctypes

    windll = getattr(ctypes, "windll", None)
    if os.name != "nt" or windll is None or not windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Run from Administrator PowerShell on Windows")
    require_machine_python(sys.executable)
    if getattr(sys, "prefix", None) != getattr(sys, "base_prefix", None):
        raise ValueError("Use the all-users Python installation, not a virtual environment")
    root = Path(os.environ["ProgramFiles"]) / "AtomicControl"
    state = Path(os.environ["ProgramData"]) / "AtomicControl"
    config_file = state / "agent.json"
    config = json.loads(config_file.read_text())
    key = root / "job-signing-public.pem"
    if Path(config["public_key_file"]) != key or Path(config["state_root"]) != state / "jobs":
        raise ValueError("Unsupported existing installation paths")

    def no_reparse(path):
        for entry in [*reversed(path.parents), path]:
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Update paths cannot contain links or reparse points")

    for entry in [root, state, config_file, key, Path(sys.executable)]:
        no_reparse(entry)
    raw = (bundle / "manifest.json").read_bytes()
    claims = jwt.decode(
        (bundle / "manifest.jwt").read_text(),
        key.read_text(),
        algorithms=["RS256"],
        audience=config["actor_id"],
        issuer="atomic-control-package",
        options={"require": ["exp", "iat", "type", "manifest_sha256"]},
    )
    if (
        claims["type"] != "windows-runtime-package-v1"
        or claims["manifest_sha256"] != hashlib.sha256(raw).hexdigest()
    ):
        raise ValueError("Runtime package signature mismatch")
    manifest = json.loads(raw)
    included = json.loads((bundle / "agent.json").read_text())
    if manifest["mode"] != "configuration_only" or any(
        included.get(k) != config.get(k) for k in ["actor_id", "hostname", "os", "api_url"]
    ):
        raise ValueError("Use a configuration-only package for this exact enrolled actor")
    if (bundle / "job-signing-public.pem").read_bytes().strip() != key.read_bytes().strip():
        raise ValueError("Update cannot replace the pinned signing key")
    for name, expected in manifest["files"].items():
        parts = PurePosixPath(name)
        if parts.is_absolute() or ".." in parts.parts or "\\" in name or ":" in name:
            raise ValueError("Unsafe runtime package path")
        path = bundle / name
        for entry in [path, *list(path.parents)[: len(parts.parts)]]:
            no_reparse(entry)
        if (
            not path.is_file()
            or path.stat().st_size > 2_000_000
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("Runtime package checksum mismatch")
    service = subprocess.run(
        ["sc.exe", "query", "AtomicControlAgent"], capture_output=True, text=True, check=True
    )
    if "STOPPED" not in service.stdout:
        raise ValueError("Stop AtomicControlAgent before updating")
    if (state / "jobs/active.json").exists():
        raise ValueError("Reconcile the active job before updating")
    if check_only:
        print("Signed update checks passed; no files changed")
        return
    credential = Path(config["credential_file"])
    before = hashlib.sha256(credential.read_bytes()).hexdigest()
    stage = root / ("runtime-update-" + uuid4().hex)
    stage.mkdir()
    subprocess.run(
        [
            "icacls.exe",
            str(stage),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
        ],
        capture_output=True,
        check=True,
    )
    for name in manifest["files"]:
        if name.startswith("runtime/"):
            target = stage / name.removeprefix("runtime/")
            target.parent.mkdir(parents=True, exist_ok=True)
            content = (bundle / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != manifest["files"][name]:
                raise ValueError("Package changed during update")
            target.write_bytes(content)
    subprocess.run(
        [sys.executable, "-I", "-m", "pip", "install", "-r", str(stage / "requirements.txt")], check=True
    )
    post_install = Path(sysconfig.get_path("scripts")) / "pywin32_postinstall.py"
    if not post_install.is_file():
        raise ValueError(
            "The all-users Python is missing pywin32's post-install script; leave the service stopped"
        )
    subprocess.run([sys.executable, "-I", str(post_install), "-install"], check=True)
    subprocess.run(
        [
            sys.executable,
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
    # Refresh service registration under this Python too, so migrating away from
    # a per-user interpreter never leaves the daemon running the old installation.
    subprocess.run(
        [sys.executable, "-I", "-m", "apps.agent.service", "--startup", "auto", "update"], check=True
    )
    if (
        enable_on_demand
        or not config.get("profile_sync_enabled")
        or config.get("python_path") != sys.executable
    ):
        if enable_on_demand:
            config.update(delivery_mode="on_demand", catalog_verification_enabled=False)
        config["profile_sync_enabled"] = True
        config["python_path"] = sys.executable
        backup = state / ("agent.before-runtime-update-" + uuid4().hex + ".json")
        shutil.copyfile(config_file, backup)
        config_file.write_text(json.dumps(config, indent=2))
    if hashlib.sha256(credential.read_bytes()).hexdigest() != before:
        raise RuntimeError("Credential changed unexpectedly; leave service stopped")
    print(
        "Runtime updated in place; credentials, profiles, signing key and old catalog preserved. Service remains stopped."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-on-demand", action="store_true")
    parser.add_argument(
        "--enable-profile-sync", action="store_true", help="Enabled automatically by this runtime update"
    )
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    update(Path(__file__).resolve().parent, args.enable_on_demand, args.check_only)
