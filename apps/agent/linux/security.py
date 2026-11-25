"""Root-owned configuration and crash-safe credential storage."""

import json
import os
import stat
from pathlib import Path
from uuid import uuid4


def protected(path: Path, private: bool = False):
    if not path.is_absolute():
        raise ValueError("Protected paths must be absolute")
    for entry in [*reversed(path.parents), path]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Agent paths must be root-owned, without symlinks or group/other write access")
    if private and (not path.is_file() or path.stat().st_mode & 0o077):
        raise ValueError("Credentials must be a root-only regular file")


def write_json(path: Path, value: dict, mode: int = 0o600, exclusive: bool = False):
    protected(path.parent)
    if path.exists() or path.is_symlink():
        protected(path, private=mode == 0o600)
    temp = path.parent / ("." + path.name + "." + uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        # The daemon uses umask 0077, but profile-readable job/config files intentionally use 0644.
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            os.link(temp, path, follow_symlinks=False)
            temp.unlink()
        else:
            temp.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


def save_credential(path: Path, value: dict):
    if os.geteuid() != 0:
        raise RuntimeError("Linux credential storage requires root")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    protected(path.parent)
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("Credential directory must be root-only")
    write_json(path, value)


def load_credential(path: Path):
    protected(path, private=True)
    return json.loads(path.read_text())


def protected_tree(root: Path):
    protected(root)

    def fail_walk(error):
        raise error

    for folder, directories, files in os.walk(root, followlinks=False, onerror=fail_walk):
        for name in directories + files:
            entry = Path(folder) / name
            info = entry.lstat()
            if (
                info.st_uid != 0
                or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            ):
                raise ValueError(
                    "Catalog content must be root-owned regular files/directories without writable groups or links"
                )
