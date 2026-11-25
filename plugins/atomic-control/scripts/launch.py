#!/usr/bin/env python3
"""Standard-library bootstrap. Execute the MCP bridge in the configured project's virtual environment."""

import json
import os
import sys
from pathlib import Path


def main():
    if sys.platform not in {"darwin", "linux"}:
        raise SystemExit("The local dashboard plugin currently supports macOS and Linux hosts")
    config_file = Path(__file__).resolve().parents[1] / ".project.local.json"
    if not config_file.is_file():
        raise SystemExit("Atomic Control plugin is not configured. In the project, run .venv/bin/python -m scripts.configure_codex_plugin, then install/refresh this plugin")
    config = json.loads(config_file.read_text())
    root = Path(config["project_root"])
    python = root / ".venv/bin/python"
    if not root.is_absolute() or not python.is_file() or not (root / "apps/codex_plugin/server.py").is_file():
        raise SystemExit("Configured Atomic Control checkout/virtual environment is unavailable. Reconfigure the plugin")
    os.chdir(root)
    os.execv(str(python), [str(python), "-m", "apps.codex_plugin.server", "--config", str(config_file)])


if __name__ == "__main__":
    main()
