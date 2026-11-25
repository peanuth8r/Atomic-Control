import json
from pathlib import Path

import pytest
from mcp import Client
from pydantic import ValidationError

from apps.codex_plugin.server import create_server
from apps.codex_plugin.settings import PluginSettings
from scripts.configure_codex_plugin import ROOT, configure, mcp_config


def configuration(**extra):
    return PluginSettings(
        project_root=ROOT,
        remote_mcp_url="https://mcp.example.test/mcp",
        remote_dashboard_url="https://control.example.test",
        **extra,
    )


async def test_plugin_uses_native_authenticated_mcp_and_only_local_dashboard_links(tmp_path):
    settings = configuration()
    config = mcp_config(settings)
    assert config["mcpServers"]["atomic_control"] == {
        "type": "http",
        "url": settings.remote_mcp_url,
        "oauth": {
            "clientId": "atomic-control-codex",
            "callbackUrl": "http://127.0.0.1:1456/callback",
            "callbackPort": 1456,
        },
    }
    async with Client(create_server(settings)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert names == {"atomic_dashboard_start", "atomic_dashboard_status"}
        status = (await client.call_tool("atomic_dashboard_start", {})).structured_content
        assert status["mode"] == "real" and status["outcome"] == "configured" and not status["managed"]
        assert (await client.call_tool("atomic_request_test", {})).is_error
    configure(settings, tmp_path)
    saved = json.loads((tmp_path / ".project.local.json").read_text())
    assert saved["mode"] == "remote" and not any("token" in key or "secret" in key for key in saved)
    assert (tmp_path / ".project.local.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "url",
    [
        "http://control.test",
        "https://user:password@control.test",
        "https://control.test/mcp?token=secret",
        "https://control.test/#token",
        "https://control.test:99999",
    ],
)
def test_configuration_rejects_insecure_or_credential_bearing_urls(url):
    with pytest.raises(ValidationError):
        PluginSettings(project_root=ROOT, remote_mcp_url=url, remote_dashboard_url="https://control.test")


def test_connection_configuration_is_required_and_removed_mode_is_rejected():
    with pytest.raises(ValidationError):
        PluginSettings(project_root=ROOT)
    with pytest.raises(ValidationError):
        configuration(mode="demo")


def test_plugin_package_manifest_paths_are_complete():
    plugin = ROOT / "plugins/atomic-control"
    manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
    assert manifest["name"] == plugin.name
    for path in [manifest["skills"], manifest["mcpServers"], manifest["interface"]["composerIcon"]]:
        assert path.startswith("./") and ".." not in Path(path).parts and (plugin / path).exists()
