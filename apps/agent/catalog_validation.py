from pathlib import Path

from apps.api.app.catalog.parser import ALLOWED_EXECUTORS, parse_file
from apps.api.app.services.common import fingerprint


def validate_catalog(root: Path, snapshot: dict, revision: str, root_owned: bool = False):
    import subprocess

    if revision != snapshot["source_revision"]:
        raise ValueError("Installed catalog revision differs from grant")
    # Linux profiles read a root-owned checkout from a read-only mount. Trust only this
    # already ownership-validated directory, never a global safe.directory wildcard.
    git = (
        ["/usr/bin/git", "--no-optional-locks", "-c", "safe.directory=" + str(root)]
        if root_owned
        else ["git"]
    )
    import os

    if os.name == "nt":
        from .windows_catalog import machine_git

        git = [machine_git()]
    actual_revision = subprocess.check_output([*git, "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(
        [*git, "-C", str(root), "status", "--porcelain", "--untracked-files=all", "--ignored"], text=True
    )
    if actual_revision != revision or dirty:
        raise ValueError("Catalog checkout changed or is not pinned")
    technique = snapshot["technique"]
    import re

    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
        raise ValueError("Invalid technique")
    candidates = parse_file(root / "atomics" / technique / (technique + ".yaml"))
    definition = next((t for t in candidates if t["auto_generated_guid"] == snapshot["atomic_guid"]), None)
    if (
        definition is None
        or fingerprint(definition) != snapshot["content_sha256"]
        or definition != snapshot["definition"]
    ):
        raise ValueError("Local Atomic definition hash mismatch")
    if definition["executor"]["name"] not in ALLOWED_EXECUTORS:
        raise ValueError("Unsupported executor")
    # The full clean pinned checkout also binds helper scripts / payloads tracked by Git.
    return definition
