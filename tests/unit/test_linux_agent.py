import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from apps.agent.linux import broker, runner, security
from apps.agent.linux.bootstrap import validate_bundle
from apps.agent.linux.commands import commands
from apps.agent.linux.identity import validate_identity


def profile(root=False):
    return {
        "id": str(uuid4()),
        "expected_sid": "uid:0" if root else "uid:1001",
        "account": "root" if root else "atomic-user",
        "privilege": "elevated" if root else "standard",
        "enabled": True,
    }


def identity(p):
    uid = int(p["expected_sid"].split(":")[1])
    return {
        "platform": "linux",
        "expected_profile_id": p["id"],
        "expected_account_sid": p["expected_sid"],
        "actual_account_sid": p["expected_sid"],
        "actual_account_name": p["account"],
        "uid": uid,
        "euid": uid,
        "gid": uid,
        "egid": uid,
        "groups": [uid],
        "capabilities": "0" * 16,
        "permitted_capabilities": "0" * 16,
        "ambient_capabilities": "0" * 16,
        "bounding_capabilities": "0" * 16,
        "no_new_privileges": True,
        "elevated": uid == 0,
        "process_id": 1234,
        "verified": False,
    }


def snapshot(action="execute"):
    return {
        "action": action,
        "input_values": {"message": "reviewed-default"},
        "definition": {
            "supported_platforms": ["linux"],
            "input_arguments": {"message": {"default": "reviewed-default"}},
            "executor": {
                "name": "bash",
                "command": "printf '%s' '#{message}'",
                "cleanup_command": "printf cleanup",
            },
            "dependency_executor_name": "sh",
            "dependencies": [
                {"prereq_command": "test -d '#{PathToAtomicsFolder}'", "get_prereq_command": "MUST NEVER RUN"}
            ],
        },
    }


def test_shell_plan_uses_exact_defaults_and_never_fetches_dependencies():
    s = snapshot()
    assert (
        commands(s, Path("/opt/atomic-control/atomic-red-team"))[-1][-1] == "printf '%s' 'reviewed-default'"
    )
    s["action"] = "check"
    plan = commands(s, Path("/opt/atomic-control/atomic-red-team"))
    assert plan == [["/bin/sh", "-c", "test -d '/opt/atomic-control/atomic-red-team/atomics'"]]
    assert "MUST NEVER RUN" not in str(plan)
    s["action"] = "cleanup"
    assert commands(s, Path("/catalog"))[0][-1] == "printf cleanup"


@pytest.mark.parametrize(
    "change",
    ["override", "powershell", "wrong_platform", "missing_default", "unknown_action", "dependency_executor"],
)
def test_unsupported_commands_rejected(change):
    s = snapshot()
    if change == "override":
        s["input_values"]["message"] = "unapproved"
    if change == "powershell":
        s["definition"]["executor"]["name"] = "powershell"
    if change == "wrong_platform":
        s["definition"]["supported_platforms"] = ["windows"]
    if change == "missing_default":
        s["definition"]["executor"]["command"] = "echo #{missing}"
    if change == "unknown_action":
        s["action"] = "get_prereqs"
    if change == "dependency_executor":
        s["action"] = "check"
        s["definition"]["dependency_executor_name"] = "powershell"
    with pytest.raises(ValueError):
        commands(s, Path("/catalog"))


@pytest.mark.parametrize("root", [False, True])
def test_linux_identity_profiles_are_distinct(root):
    p = profile(root)
    assert validate_identity(identity(p), p)["verified"]
    wrong = profile(not root)
    with pytest.raises(ValueError):
        validate_identity(identity(wrong), p)


@pytest.mark.parametrize(
    "field,value",
    [
        ("euid", 0),
        ("egid", 0),
        ("groups", [0, 1001]),
        ("capabilities", "0000000000000001"),
        ("bounding_capabilities", "0000000000000001"),
        ("permitted_capabilities", "0000000000000001"),
        ("no_new_privileges", False),
        ("actual_account_name", "another-user"),
    ],
)
def test_standard_identity_rejects_privilege_or_account_mismatch(field, value):
    p = profile()
    evidence = {**identity(p), field: value}
    with pytest.raises(ValueError):
        validate_identity(evidence, p)


def test_systemd_profile_runs_fixed_wrapper_under_the_bound_uid(monkeypatch):
    import pwd

    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    command = broker.profile_command(
        {"python_path": "/opt/atomic-control/venv/bin/python"},
        profile(),
        "atomic-control-job-" + str(uuid4()) + ".service",
        120,
        ["-m", "apps.agent.linux.runner"],
        Path("/var/lib/atomic-control/work"),
    )
    assert "--property=User=1001" in command and "--property=Group=1001" in command
    assert "--property=NoNewPrivileges=yes" in command
    assert "--property=CapabilityBoundingSet=" in command
    assert "--property=KillMode=control-group" in command
    assert command[-3:] == ["-I", "-m", "apps.agent.linux.runner"]
    with pytest.raises(ValueError, match="UID changed"):
        broker.profile_command(
            {"python_path": "unused"}, {**profile(), "expected_sid": "uid:1002"}, "unit", 10, [], Path("/")
        )


def test_harmless_shell_output_nonzero_timeout_and_output_limit(tmp_path):
    assert runner.run_commands([["/bin/sh", "-c", "printf hello"]], 2, tmp_path) == (
        "succeeded",
        0,
        "hello",
        "",
    )
    assert runner.run_commands([["/bin/sh", "-c", "printf failure >&2; exit 7"]], 2, tmp_path) == (
        "failed",
        7,
        "",
        "failure",
    )
    assert runner.run_commands([["/bin/sh", "-c", "sleep 2"]], 0.1, tmp_path)[0] == "timed_out"
    result = runner.run_commands([[sys.executable, "-I", "-c", "print('x'*70000)"]], 3, tmp_path)
    assert result[0] == "inconclusive" and len(result[2]) == 65536
    assert runner.run_commands([], 2, tmp_path) == ("succeeded", 0, "", "")


def test_runner_rejects_wrong_identity_before_any_shell(monkeypatch, tmp_path):
    p = profile()
    config = {"public_key_file": str(tmp_path / "public.pem"), "catalog_root": "/catalog"}
    (tmp_path / "public.pem").write_text("unused")
    config_file, job_file = tmp_path / "config.json", tmp_path / "job.json"
    config_file.write_text(json.dumps(config))
    job_file.write_text(json.dumps({"snapshot": snapshot()}))
    monkeypatch.setattr(runner, "protected", lambda *_: None)
    monkeypatch.setattr(runner, "verify_job", lambda *_: p)
    monkeypatch.setattr(runner, "capture_identity", lambda _: {**identity(p), "euid": 0})

    def forbidden(*_):
        raise AssertionError("No shell may start after identity failure")

    monkeypatch.setattr(runner, "run_commands", forbidden)
    result = runner.run(config_file, job_file, tmp_path)
    assert result["status"] == "failed" and not result["identity"]["verified"]


def test_bootstrap_rejects_wrong_platform_host_expiry_before_enrollment():
    config = {
        "actor_id": str(uuid4()),
        "hostname": "linux-one",
        "api_url": "https://control.example.test",
        "os": "linux",
    }
    bootstrap = {**config, "mode": "enrollment", "enrollment_token": "x" * 64, "expires_at": 1000}
    validate_bundle(bootstrap, config, {"LINUX-ONE"}, 900)
    for override in [
        {"os": "windows"},
        {"hostname": "linux-two"},
        {"expires_at": 0},
        {"mode": "configuration_only"},
    ]:
        with pytest.raises(ValueError):
            validate_bundle({**bootstrap, **override}, config, {"linux-one"}, 900)


def test_durable_journal_is_exclusive_and_recovery_never_replays(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "protected", lambda *_, **__: None)
    journal = tmp_path / "active.json"
    job = {"attempt_id": str(uuid4())}
    security.write_json(journal, job, exclusive=True)
    with pytest.raises(FileExistsError):
        security.write_json(journal, {"attempt_id": str(uuid4())}, exclusive=True)
    assert json.loads(journal.read_text()) == job and journal.stat().st_mode & 0o777 == 0o600
    stopped = []
    monkeypatch.setattr(broker, "protected", lambda *_, **__: None)
    monkeypatch.setattr(broker, "stop_unit", stopped.append)
    instance = object.__new__(broker.Broker)
    instance.journal = journal
    with pytest.raises(RuntimeError, match="Uncertain prior Linux job"):
        instance.recover()
    assert stopped == [broker.unit_name(job["attempt_id"])] and journal.exists()


def test_credential_storage_and_catalog_reject_unprotected_paths(tmp_path):
    path = tmp_path / "credential.json"
    path.write_text('{"credential":"fake"}')
    with pytest.raises(ValueError):
        security.load_credential(path)
    with pytest.raises(ValueError):
        security.protected_tree(tmp_path)


def test_stopping_unknown_or_active_unit_requires_confirmed_stop(monkeypatch):
    unit = broker.unit_name(str(uuid4()))
    monkeypatch.setattr(broker, "verify_cgroup_empty", lambda *_: None)
    replies = iter(
        [
            "LoadState=loaded\nActiveState=active\nControlGroup=/system.slice/test.service",
            "",
            "ActiveState=inactive",
        ]
    )
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, next(replies), "")

    monkeypatch.setattr(broker.subprocess, "run", execute)
    broker.stop_unit(unit)
    assert [broker.SYSTEMCTL, "stop", unit] in calls
    monkeypatch.setattr(
        broker.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(
            stdout="ActiveState=active\nControlGroup=/system.slice/test.service"
        ),
    )
    with pytest.raises(RuntimeError, match="Cannot establish"):
        broker.stop_unit(unit)
    with pytest.raises(ValueError):
        broker.unit_name("../../unrelated")


@pytest.mark.parametrize("failure", [None, "acknowledgement", "cancel_before_dispatch", "connectivity"])
def test_broker_journals_dispatch_and_preserves_unknown_outcomes(monkeypatch, tmp_path, failure):
    import pwd
    import threading
    import time

    p = profile()
    p["validated"] = True
    job = {
        "run_id": str(uuid4()),
        "attempt_id": str(uuid4()),
        "fence": "a" * 64,
        "snapshot": {"timeout_seconds": 10},
    }
    work = tmp_path / "work"
    work.mkdir()
    config = {
        "work_root": str(work),
        "config_file": "/etc/atomic-control/agent.json",
        "profiles": [p],
        "actor_id": str(uuid4()),
        "hostname": "linux-one",
        "os_version": "Linux",
        "revision": "a" * 40,
    }
    instance = object.__new__(broker.Broker)
    instance.config, instance.root, instance.journal = config, tmp_path, tmp_path / "active.json"
    instance.public_key, instance.stop = "unused", threading.Event()
    monkeypatch.setattr(broker, "verify_job", lambda *_: p)
    monkeypatch.setattr(security, "protected", lambda *_, **__: None)
    monkeypatch.setattr(broker.os, "chown", lambda *_: None)
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    monkeypatch.setattr(broker, "profile_command", lambda *_: ["mock-systemd-run"])
    stops, posts = [], []
    monkeypatch.setattr(broker, "stop_unit", stops.append)

    class Client:
        def post(self, path, payload=None):
            posts.append(path)
            if path.endswith("/result") and failure == "acknowledgement":
                raise RuntimeError("Lost result acknowledgement")
            if path == "agents/heartbeat" and failure == "connectivity":
                raise RuntimeError("Connection lost")
            return {
                "cancel_requested": failure == "cancel_before_dispatch",
                "lease_expires_at": time.time() + 60,
            }

    instance.client = Client()

    class Process:
        returncode = 0

        def __init__(self, command, stdout, **kwargs):
            assert instance.journal.exists(), "No dispatch before durable journal"
            if failure == "cancel_before_dispatch":
                raise AssertionError("Cancelled jobs must not dispatch")
            stdout.write(json.dumps({"status": "succeeded", "exit_code": 0}).encode())
            stdout.flush()
            self.polls = 0

        def poll(self):
            self.polls += 1
            return None if self.polls == 1 else 0

        def terminate(self):
            pass

        def wait(self, **kwargs):
            return 0

    monkeypatch.setattr(broker.subprocess, "Popen", Process)
    if failure:
        with pytest.raises(RuntimeError):
            instance.execute(job)
        assert instance.journal.exists()
        if failure != "cancel_before_dispatch":
            assert stops == [broker.unit_name(job["attempt_id"])]
    else:
        result = instance.execute(job)
        assert not instance.journal.exists() and result["attempt_id"] == job["attempt_id"]
        assert result["fence"] == job["fence"] and stops == [broker.unit_name(job["attempt_id"])]
    assert (
        not any(path.endswith("/result") for path in posts)
        if failure in {"connectivity", "cancel_before_dispatch"}
        else any(path.endswith("/result") for path in posts)
    )


def test_installer_manifest_rejects_tampering_traversal_and_links(tmp_path):
    import hashlib

    from apps.agent.packaging.install_linux import validate_files

    source = tmp_path / "runtime.py"
    source.write_text("# reviewed source")
    manifest = {"files": {"runtime.py": hashlib.sha256(source.read_bytes()).hexdigest()}}
    validate_files(tmp_path, manifest)
    source.write_text("# changed")
    with pytest.raises(ValueError, match="checksum"):
        validate_files(tmp_path, manifest)
    with pytest.raises(ValueError, match="Invalid package path"):
        validate_files(tmp_path, {"files": {"../escape": "fake"}})
    source.unlink()
    source.symlink_to(tmp_path / "other")
    with pytest.raises(ValueError, match="links"):
        validate_files(tmp_path, manifest)


def test_linux_signed_grant_cannot_be_dispatched_as_a_windows_job(monkeypatch):
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from apps.agent.execution_broker import verify_job
    from apps.api.app.services.common import fingerprint

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    p = {**profile(), "validated": True, "profile_key": "standard-user"}
    actor = str(uuid4())
    s = {
        **snapshot(),
        "actor_id": actor,
        "actor_os": "linux",
        "execution_profile_id": p["id"],
        "expected_sid": p["expected_sid"],
        "profile_key": p["profile_key"],
        "privilege": p["privilege"],
        "simulated": False,
        "timeout_seconds": 120,
    }
    job = {
        "run_id": str(uuid4()),
        "attempt_id": str(uuid4()),
        "fence": "a" * 64,
        "snapshot": s,
        "snapshot_hash": fingerprint(s),
        "lease_expires_at": time.time() + 60,
    }
    config = {
        "actor_id": actor,
        "os": "linux",
        "profiles": [p],
        "catalog_root": "/catalog",
        "revision": "a" * 40,
    }
    checks = []
    monkeypatch.setattr(security, "protected_tree", lambda path: checks.append(path))
    monkeypatch.setattr("apps.agent.execution_broker.validate_catalog", lambda *_: None)
    job["grant"] = jwt.encode(
        {**job, "iss": "atomic-control", "aud": actor, "iat": int(time.time()), "exp": int(time.time()) + 60},
        private,
        algorithm="RS256",
    )
    assert verify_job(job, config, public) == p and checks == [Path("/catalog")]
    with pytest.raises(ValueError, match="platform differs"):
        verify_job(job, {**config, "os": "windows"}, public)
    with pytest.raises(ValueError, match="Signed job"):
        verify_job({**job, "snapshot": {**s, "actor_os": "windows"}}, config, public)


def test_daemon_umask_does_not_hide_profile_readable_configuration(monkeypatch, tmp_path):
    import os

    monkeypatch.setattr(security, "protected", lambda *_, **__: None)
    previous = os.umask(0o077)
    try:
        path = tmp_path / "agent.json"
        security.write_json(path, {"profiles": []}, 0o644)
        assert path.stat().st_mode & 0o777 == 0o644
        private = tmp_path / "credentials.json"
        security.write_json(private, {"credential": "fake"})
        assert private.stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(previous)


def test_root_owned_catalog_uses_scoped_git_trust_and_checks_ignored_files(monkeypatch):
    from apps.agent.catalog_validation import validate_catalog

    calls = []

    def query(command, **kwargs):
        calls.append(command)
        return "a" * 40 if "rev-parse" in command else "!! unreviewed-ignored-payload\n"

    monkeypatch.setattr(subprocess, "check_output", query)
    with pytest.raises(ValueError, match="changed or is not pinned"):
        validate_catalog(
            Path("/opt/atomic-control/atomic-red-team"), {"source_revision": "a" * 40}, "a" * 40, True
        )
    assert all(
        "safe.directory=/opt/atomic-control/atomic-red-team" in call and "--no-optional-locks" in call
        for call in calls
    )
    assert "--ignored" in calls[-1]


def test_cgroup_stop_checks_descendant_processes_and_refuses_path_escape(tmp_path):
    group = tmp_path / "system.slice/test.service"
    nested = group / "nested"
    nested.mkdir(parents=True)
    (group / "cgroup.procs").write_text("")
    (nested / "cgroup.procs").write_text("1234\n")
    with pytest.raises(RuntimeError, match="still contains processes"):
        broker.verify_cgroup_empty("/system.slice/test.service", tmp_path)
    (nested / "cgroup.procs").write_text("")
    broker.verify_cgroup_empty("/system.slice/test.service", tmp_path)
    with pytest.raises(RuntimeError, match="Invalid execution cgroup"):
        broker.verify_cgroup_empty("/../../unrelated", tmp_path)
