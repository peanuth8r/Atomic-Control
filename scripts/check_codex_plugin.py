"""Read-only stdio dashboard-link smoke check; no service or job is started."""

import asyncio
import json
import tempfile
from pathlib import Path

from mcp import Client, StdioServerParameters

from apps.codex_plugin.settings import PluginSettings
from scripts.configure_codex_plugin import ROOT


async def check():
    settings = PluginSettings(
        project_root=ROOT,
        remote_mcp_url="https://localhost:19444/mcp",
        remote_dashboard_url="https://localhost:19443",
    )
    with tempfile.TemporaryDirectory(prefix="atomic-plugin-check-") as folder:
        config = Path(folder) / "settings.json"
        config.write_text(settings.model_dump_json())
        config.chmod(0o600)
        transport = StdioServerParameters(
            command=str(settings.python),
            args=["-m", "apps.codex_plugin.server", "--config", str(config)],
            cwd=ROOT,
        )
        async with Client(transport) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert names == {"atomic_dashboard_start", "atomic_dashboard_status"}
            status = (await client.call_tool("atomic_dashboard_status", {})).structured_content
            assert status["mode"] == "real" and not status["managed"]
            print(json.dumps({"dashboard_link_tools": sorted(names), "real_https_mcp_required": True}))


if __name__ == "__main__":
    asyncio.run(check())
