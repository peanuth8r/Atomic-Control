import pytest

from apps.codex_plugin import dashboard
from apps.codex_plugin.dashboard import Dashboard
from apps.codex_plugin.settings import PluginSettings


def settings(tmp_path):
    return PluginSettings(
        project_root=tmp_path,
        remote_mcp_url="https://localhost:19444/mcp",
        remote_dashboard_url="https://control.example.test",
    )


def test_dashboard_links_do_not_start_or_stop_deployment_processes(tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(dashboard.webbrowser, "open", lambda url: opened.append(url) or True)
    instance = Dashboard(settings(tmp_path))
    assert instance.start()["outcome"] == "configured"
    assert opened == []
    assert instance.start(open_browser=True)["browser_opened"]
    assert opened == ["https://control.example.test"]
    assert not hasattr(instance, "stop")


def test_relative_checkout_is_rejected(tmp_path):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PluginSettings(
            project_root="relative",
            remote_mcp_url="https://mcp.example.test",
            remote_dashboard_url="https://control.example.test",
        )
