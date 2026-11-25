"""Open the configured real dashboard; deployment lifecycle is managed separately."""

import webbrowser

from .settings import PluginSettings


class Dashboard:
    def __init__(self, settings: PluginSettings):
        self.settings = settings

    def status(self):
        return {
            "ok": True,
            "outcome": "configured",
            "mode": "real",
            "dashboard_url": self.settings.dashboard_url,
            "mcp_url": self.settings.remote_mcp_url,
            "managed": False,
            "note": "Authenticate the separate HTTPS MCP connection through Codex. Configuration does not establish connection readiness.",
        }

    def start(self, open_browser=False):
        result = self.status()
        if open_browser:
            result["browser_opened"] = bool(webbrowser.open(self.settings.dashboard_url))
        return result
