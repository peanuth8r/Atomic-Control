"""Install one package-selected official catalog; never execute Atomic content."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from apps.api.app.catalog.parser import parse_file
from apps.api.app.services.common import fingerprint

from .catalog_config import REMOTE, SOURCE, DefinitionHash


class PackageCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    protocol: int = Field(ge=1, le=1)
    actor_id: str
    hostname: str
    source: str
    revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    tests: list[DefinitionHash] = Field(min_length=1, max_length=10000)


def manifest(value, config):
    result = PackageCatalog.model_validate(value).model_dump()
    UUID(result["actor_id"])
    if result["source"] != SOURCE or any(
        result[k] != config[k] for k in ("actor_id", "hostname", "revision")
    ):
        raise ValueError("Catalog manifest does not match this Windows actor and revision")
    if len({test["guid"] for test in result["tests"]}) != len(result["tests"]):
        raise ValueError("Duplicate catalog definitions")
    return result


def machine_git():
    if sys.platform != "win32":
        result = shutil.which("git")
        if not result:
            raise RuntimeError("Git is required")
        return result
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as key:
        for name in ("ProgramFilesDir", "ProgramFilesDir (x86)"):
            try:
                root = Path(winreg.QueryValueEx(key, name)[0])
            except OSError:
                continue
            for folder in ("cmd", "bin"):
                candidate = root / "Git" / folder / "git.exe"
                if candidate.is_file():
                    return str(candidate)
    raise RuntimeError("Install Git for Windows for all users under Program Files before catalog setup")


def git(root, *arguments, timeout=60):
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {"SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_ALLOW_PROTOCOL="https",
        GIT_PROTOCOL_FROM_USER="0",
    )
    command = [
        machine_git(),
        "--no-optional-locks",
        "-c",
        "safe.directory=" + str(root),
        "-c",
        "core.hooksPath=" + os.devnull,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.sslVerify=true",
        "-c",
        "http.followRedirects=false",
        "-c",
        "fetch.fsckObjects=true",
        "-C",
        str(root),
        *arguments,
    ]
    if sys.platform == "win32":
        command[1:1] = ["-c", "http.sslBackend=schannel"]
    try:
        return subprocess.run(
            command, env=env, capture_output=True, text=True, check=True, timeout=timeout
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError(
            "Catalog Git operation failed; check machine-wide Git and verified HTTPS access to GitHub"
        ) from None


def no_reparse(root):
    paths = [root]
    for folder, dirs, files in os.walk(root, followlinks=False):
        paths.extend(Path(folder) / name for name in dirs + files)
    for path in paths:
        info = path.lstat()
        if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("Catalog paths must not contain symbolic links or reparse points")


def protect_tree(root):
    # Parent is the installer-protected Program Files directory. Reset child ACLs to it.
    for args in (["/setowner", "*S-1-5-32-544", "/T", "/Q"], ["/reset", "/T", "/Q"]):
        subprocess.run(["icacls.exe", str(root), *args], check=True, capture_output=True)


def trust_checkout(root):
    command = [machine_git(), "config", "--system"]
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    result = subprocess.run(
        [*command, "--get-all", "safe.directory"], env=env, capture_output=True, text=True
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("Cannot inspect machine Git catalog trust")
    directory = str(root).replace("\\", "/")
    if directory not in result.stdout.splitlines():
        subprocess.run(
            [*command, "--add", "safe.directory", directory], env=env, check=True, capture_output=True
        )


def verify_checkout(root, value):
    no_reparse(root)
    if (
        not (root / ".git").is_dir()
        or git(root, "rev-parse", "HEAD") != value["revision"]
        or git(root, "status", "--porcelain", "--untracked-files=all", "--ignored")
    ):
        raise RuntimeError("Catalog must be the exact clean selected Git commit")
    definitions = {}
    for technique in {test["technique"] for test in value["tests"]}:
        for definition in parse_file(root / "atomics" / technique / (technique + ".yaml")):
            definitions[definition["auto_generated_guid"]] = definition
    for test in value["tests"]:
        if test["guid"] not in definitions or fingerprint(definitions[test["guid"]]) != test["sha256"]:
            raise RuntimeError("Official catalog content does not match imported definitions")


def install(config, value, install_root):
    value = manifest(value, config)
    root = install_root / "atomic-red-team"
    if root.exists():
        no_reparse(root)
        protect_tree(root)
        verify_checkout(root, value)
    else:
        staged = install_root / ("catalog-stage-" + uuid4().hex)
        staged.mkdir()
        try:
            git(staged, "init", "--quiet", "--template=")
            git(staged, "remote", "add", "origin", REMOTE)
            git(staged, "fetch", "--no-tags", "--depth=1", "origin", value["revision"], timeout=600)
            git(staged, "checkout", "--detach", value["revision"], timeout=180)
            no_reparse(staged)
            protect_tree(staged)
            verify_checkout(staged, value)
            staged.rename(root)
        except Exception:
            # Retain the protected staging directory for diagnosis. Never overwrite an existing checkout.
            raise
    trust_checkout(root)
    target = install_root / "catalog-manifest.json"
    temporary = target.with_name("catalog-manifest-" + uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(target)
    return value["revision"]


def reported_revision(config):
    try:
        root = Path(config["catalog_root"])
        value = manifest(json.loads(Path(config["catalog_manifest_file"]).read_text()), config)
        if git(root, "rev-parse", "HEAD") == value["revision"] and not git(
            root, "status", "--porcelain", "--untracked-files=all", "--ignored"
        ):
            return value["revision"]
    except (OSError, ValueError, RuntimeError, KeyError):
        pass
    return ""


def main():
    if os.name != "nt":
        raise SystemExit("Windows administrator installation required")
    import ctypes

    windows_api = getattr(ctypes, "windll", None)
    if windows_api is None or not windows_api.shell32.IsUserAnAdmin():
        raise SystemExit("Run as administrator")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    args = parser.parse_args()
    if not args.install_root.is_absolute() or args.install_root.is_symlink():
        raise SystemExit("Use a protected absolute installation path")
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    value = json.loads(args.manifest.read_text())
    revision = install(config, value, args.install_root)
    print("Catalog installed and verified:", revision)


if __name__ == "__main__":
    main()
