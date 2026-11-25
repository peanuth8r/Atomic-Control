"""Local dashboard links; Atomic operations use the authenticated HTTPS MCP server."""

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .dashboard import Dashboard
from .settings import PluginSettings, load_settings


def create_server(settings: PluginSettings):
    dashboard = Dashboard(settings)
    server = MCPServer("Atomic Control dashboard", version="0.2.0")

    @server.tool(structured_output=True, annotations=ToolAnnotations(read_only_hint=True))
    async def atomic_dashboard_status() -> dict[str, Any]:
        """Show the configured real dashboard and authenticated MCP URLs."""
        return dashboard.status()

    @server.tool(structured_output=True)
    async def atomic_dashboard_start(open_browser: bool = False) -> dict[str, Any]:
        """Return the real dashboard URL and optionally open it. Deployment services are managed separately."""
        return await asyncio.to_thread(dashboard.start, open_browser)

    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    create_server(load_settings(args.config)).run(transport="stdio")


if __name__ == "__main__":
    main()
