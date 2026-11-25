"""Explicit removal of a verified agent-managed checkout after an in-place delivery upgrade."""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


def remove_managed_checkout(config):
    if config.get("delivery_mode") != "on_demand":
        raise ValueError("Enable on-demand delivery before removing the managed checkout")
    if (Path(config["state_root"]) / "active.json").exists():
        raise ValueError("Reconcile active work first")
    expected_root = (
        Path("/opt/atomic-control")
        if config.get("os") == "linux"
        else Path(os.environ["ProgramFiles"]) / "AtomicControl"
    )
    root = Path(config["catalog_root"])
    if root != expected_root / "atomic-red-team":
        raise ValueError("Only the standard agent-managed checkout can be removed")
    if root != Path(config["public_key_file"]).parent / "atomic-red-team":
        raise ValueError("Refusing to remove a custom catalog location")
    if not root.exists():
        return
    from .artifacts import reject_links

    reject_links(root)
    if config.get("os") == "linux":
        from .linux.catalog_sync import readiness
        from .linux.security import protected_tree

        state = subprocess.run(
            ["/usr/bin/systemctl", "is-active", "atomic-control-agent"], capture_output=True, text=True
        )
        if state.stdout.strip() not in {"inactive", "failed"}:
            raise ValueError("Stop the agent before catalog removal")
        protected_tree(root)
        if any(root.iterdir()) and readiness(config)[0] != "ready":
            raise ValueError("Only a clean checkout with an applied agent receipt can be removed")
    else:
        from .windows_catalog import manifest, no_reparse, verify_checkout

        state = subprocess.run(
            ["sc.exe", "query", "AtomicControlAgent"], capture_output=True, text=True, check=True
        )
        if "STOPPED" not in state.stdout:
            raise ValueError("Stop the agent before catalog removal")
        no_reparse(root)
        if any(root.iterdir()):
            value = manifest(json.loads(Path(config["catalog_manifest_file"]).read_text()), config)
            verify_checkout(root, value)
    shutil.rmtree(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--remove-managed-checkout", required=True, action="store_true")
    args = parser.parse_args()
    if os.name == "nt":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
            raise SystemExit("Administrator required")
    elif os.geteuid() != 0:
        raise SystemExit("Root required")
    remove_managed_checkout(json.loads(args.config.read_text()))
    print("Verified managed checkout removed; no test was executed")
