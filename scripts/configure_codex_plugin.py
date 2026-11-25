"""Prepare the local Codex plugin. Does not install it, start services, or store credentials."""

import argparse
import json
import os
import shutil
from pathlib import Path

from apps.codex_plugin.settings import PluginSettings

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins/atomic-control"


def mcp_config(settings: PluginSettings):
    local = {
        "command": "python3",
        "args": ["./scripts/launch.py"],
        "cwd": ".",
        "startup_timeout_sec": 20,
        "tool_timeout_sec": 60,
    }
    return {
        "mcpServers": {
            "atomic_control_dashboard": local,
            "atomic_control": {
                "type": "http",
                "url": settings.remote_mcp_url,
                "oauth": {
                    "clientId": "atomic-control-codex",
                    "callbackUrl": "http://127.0.0.1:1456/callback",
                    "callbackPort": 1456,
                },
            },
        }
    }


def configure(settings: PluginSettings, plugin: Path = PLUGIN):
    settings.check_project()
    plugin.mkdir(parents=True, exist_ok=True)
    content = settings.model_dump_json(indent=2) + "\n"
    destination = plugin / ".project.local.json"
    if destination.is_symlink():
        raise ValueError("Local plugin configuration cannot be a symlink")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(content)
    (plugin / ".mcp.json").write_text(json.dumps(mcp_config(settings), indent=2) + "\n")
    return plugin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-url", required=True)
    parser.add_argument("--dashboard-url", required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Create a separate configured marketplace, recommended for remote profiles",
    )
    args = parser.parse_args()
    settings = PluginSettings(
        project_root=ROOT,
        remote_mcp_url=args.mcp_url,
        remote_dashboard_url=args.dashboard_url,
    )
    target = PLUGIN
    if args.output_dir:
        output = args.output_dir.resolve()
        if output.exists():
            parser.error("Output directory already exists; choose a fresh profile directory")
        target = output / "plugins/atomic-control"
        shutil.copytree(PLUGIN, target, ignore=shutil.ignore_patterns(".project.local.json", "__pycache__"))
        market = output / ".agents/plugins/marketplace.json"
        market.parent.mkdir(parents=True)
        source = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())
        source["name"] = "atomic-control-profile"
        source["interface"]["displayName"] = "Atomic Control profile"
        market.write_text(json.dumps(source, indent=2) + "\n")
    configure(settings, target)
    print("Configured plugin:", target)
    print("Mode:", settings.mode)
    print("Next: install from the Atomic Control marketplace and start a new Codex chat.")
    print("No dashboard was started and no authentication credentials were saved.")


if __name__ == "__main__":
    main()
