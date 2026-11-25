from types import SimpleNamespace

import pytest

from apps.agent.packaging import install_linux as installer


@pytest.fixture
def partial(tmp_path, monkeypatch):
    paths = SimpleNamespace(
        root=tmp_path / "opt",
        state=tmp_path / "state",
        config=tmp_path / "etc",
        unit=tmp_path / "systemd/agent.service",
    )
    for path in [
        paths.root / "runtime",
        paths.root / "venv/bin",
        paths.state / "jobs",
        paths.state / "work",
        paths.state / "secrets",
        paths.config,
        paths.unit.parent,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    (paths.root / "venv/bin/python").write_text("test interpreter")
    (paths.root / "venv/pyvenv.cfg").write_text("test environment")
    # Actual root ownership is unavailable in the macOS fixture; test the structural
    # guards independently from check_path's ownership enforcement.
    monkeypatch.setattr(installer, "check_path", lambda path: None)
    return paths


def resume(paths):
    installer.validate_resume(paths.root, paths.state, paths.config, paths.unit)


def test_resume_accepts_only_empty_unenrolled_state_without_mutating_it(partial):
    before = sorted(str(path) for path in partial.root.parent.rglob("*"))
    resume(partial)
    assert sorted(str(path) for path in partial.root.parent.rglob("*")) == before
    assert (partial.root / "venv/bin/python").read_text() == "test interpreter"


@pytest.mark.parametrize(
    "location",
    ["config", "credential", "journal", "work", "lock", "catalog", "unit", "enabled", "enabled_file"],
)
def test_resume_refuses_and_preserves_existing_configuration_credentials_or_work(partial, location):
    target = {
        "config": partial.config / "agent.json",
        "credential": partial.state / "secrets/credential.json",
        "journal": partial.state / "jobs/active.json",
        "work": partial.state / "work/evidence.json",
        "lock": partial.state / "agent.lock",
        "catalog": partial.root / "atomic-red-team",
        "unit": partial.unit,
        "enabled": partial.unit.parent / "multi-user.target.wants" / partial.unit.name,
        "enabled_file": partial.unit.parent / "multi-user.target.wants" / partial.unit.name,
    }[location]
    target.parent.mkdir(parents=True, exist_ok=True)
    if location == "enabled":
        target.symlink_to(partial.unit)
    else:
        target.write_text("preserve this state")
    with pytest.raises(ValueError):
        resume(partial)
    assert target.is_symlink() if location == "enabled" else target.read_text() == "preserve this state"


def test_resume_requires_the_existing_virtual_environment(partial):
    (partial.root / "venv/bin/python").unlink()
    with pytest.raises(ValueError, match="virtual environment"):
        resume(partial)


def test_resume_accepts_an_empty_catalog_placeholder_without_changing_it(partial):
    catalog = partial.root / "atomic-red-team"
    catalog.mkdir()
    resume(partial)
    assert catalog.is_dir() and not any(catalog.iterdir())


def test_resume_refuses_catalog_content_in_an_unenrolled_installation(partial):
    catalog = partial.root / "atomic-red-team"
    catalog.mkdir()
    marker = catalog / "preserve.txt"
    marker.write_text("existing catalog content")
    with pytest.raises(ValueError, match="empty catalog"):
        resume(partial)
    assert marker.read_text() == "existing catalog content"


@pytest.mark.parametrize("mode,status", [("mock", 200), ("real", 503)])
def test_tls_preflight_rejects_wrong_server_before_enrollment(monkeypatch, mode, status):
    import io
    import json

    class Response(io.BytesIO):
        pass

    response = Response(json.dumps({"mode": mode}).encode())
    response.status = status
    monkeypatch.setattr(
        installer, "build_opener", lambda *args: SimpleNamespace(open=lambda *args, **kwargs: response)
    )
    with pytest.raises(ValueError, match="real-mode"):
        installer.verify_server("https://control.test")


def test_tls_preflight_never_accepts_http_or_follows_redirects():
    with pytest.raises(ValueError, match="HTTPS"):
        installer.verify_server("http://control.test")
    assert installer.NoRedirects().redirect_request(None, None, 302, "", {}, "https://other.test") is None


@pytest.mark.parametrize("scenario", ["tls_failure", "check_only", "resume"])
def test_resume_installer_checks_tls_before_writes_and_reuses_venv(partial, monkeypatch, scenario):
    import hashlib
    import json
    import ssl
    import time
    from pathlib import Path

    bundle = partial.root.parent / "bundle"
    bundle.mkdir()
    monkeypatch.setattr(installer, "__file__", str(bundle / "install.py"))
    for name, path in [
        ("ROOT", partial.root),
        ("STATE", partial.state),
        ("CONFIG", partial.config),
        ("UNIT", partial.unit),
    ]:
        monkeypatch.setattr(installer, name, path)
    identity = {"os": "linux", "hostname": "linux-host-01", "actor_id": "test-actor"}
    config = {
        **identity,
        "api_url": "https://control.test",
        "state_root": str(partial.state / "jobs"),
        "work_root": str(partial.state / "work"),
        "config_file": str(partial.config / "agent.json"),
        "credential_file": str(partial.state / "secrets/credential.json"),
        "public_key_file": str(partial.root / "job-signing-public.pem"),
        "catalog_root": str(partial.root / "atomic-red-team"),
        "python_path": str(partial.root / "venv/bin/python"),
    }
    files = {
        "agent.json": json.dumps(config).encode(),
        "bootstrap.json": json.dumps(
            {
                **identity,
                "mode": "enrollment",
                "enrollment_token": "test-token",
                "expires_at": time.time() + 600,
            }
        ).encode(),
        "runtime/requirements.txt": b"# test dependencies",
        "job-signing-public.pem": b"test public key",
        "atomic-control-agent.service": b"[Service]\n# test unit",
    }
    for name, data in files.items():
        path = bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (bundle / "manifest.json").write_text(
        json.dumps(
            {**identity, "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
        )
    )
    monkeypatch.setattr(installer.platform, "node", lambda: "linux-host-01")
    original_is_dir, original_is_file = Path.is_dir, Path.is_file
    monkeypatch.setattr(
        Path, "is_dir", lambda path: True if str(path) == "/run/systemd/system" else original_is_dir(path)
    )
    prerequisites = {
        "/sys/fs/cgroup/cgroup.controllers",
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
        "/usr/bin/git",
        "/bin/bash",
        "/bin/sh",
    }
    monkeypatch.setattr(
        Path, "is_file", lambda path: True if str(path) in prerequisites else original_is_file(path)
    )
    monkeypatch.setattr(installer.subprocess, "check_output", lambda *args, **kwargs: "systemd 252\n")
    monkeypatch.setattr(installer.os, "umask", lambda value: 0o022)
    calls = []
    monkeypatch.setattr(installer.subprocess, "run", lambda command, **kwargs: calls.append(command))

    def verify(url):
        assert url == config["api_url"]
        assert not (partial.root / "runtime/requirements.txt").exists()
        if scenario == "tls_failure":
            raise ssl.SSLError("test CA not trusted")

    monkeypatch.setattr(installer, "verify_server", verify)
    args = SimpleNamespace(resume_enrollment=True, check_only=scenario == "check_only")
    if scenario == "tls_failure":
        with pytest.raises(ssl.SSLError):
            installer.install(args)
    else:
        installer.install(args)
    assert (partial.root / "venv/bin/python").read_text() == "test interpreter"
    if scenario == "resume":
        assert (partial.root / "atomic-red-team").is_dir()
        assert not any((partial.root / "atomic-red-team").iterdir())
        assert partial.unit.read_bytes() == files["atomic-control-agent.service"]
        assert any("--force-reinstall" in command for command in calls)
        assert any("apps.agent.linux.bootstrap" in command for command in calls)
        assert not any("venv" in command or "start" in command or "enable" in command for command in calls)
    else:
        assert not calls and not partial.unit.exists()
        assert not (partial.root / "runtime/requirements.txt").exists()
