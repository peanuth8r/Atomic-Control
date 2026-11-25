"""Machine-local HTTPS connection settings; authentication stays in Codex."""

import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, model_validator


class PluginSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_root: Path
    mode: Literal["remote"] = "remote"
    remote_mcp_url: str
    remote_dashboard_url: str

    @model_validator(mode="after")
    def validate_configuration(self):
        if not self.project_root.is_absolute():
            raise ValueError("Use an absolute project path")
        for url in [self.remote_mcp_url, self.remote_dashboard_url]:
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or any(ord(c) < 33 for c in url)
            ):
                raise ValueError(
                    "MCP and dashboard require HTTPS URLs without embedded credentials, query or fragment"
                )
            if parsed.port is not None and parsed.port < 1:
                raise ValueError("Invalid HTTPS port")
        return self

    @property
    def dashboard_url(self):
        return self.remote_dashboard_url

    @property
    def python(self):
        return self.project_root / ".venv/bin/python"

    def check_project(self):
        if not self.python.is_file() or not (self.project_root / "apps/mcp/server.py").is_file():
            raise ValueError("Atomic Control checkout/virtual environment is missing")


def load_settings(path: Path) -> PluginSettings:
    return PluginSettings.model_validate(json.loads(path.read_text()))
