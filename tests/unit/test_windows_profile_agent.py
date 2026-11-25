"""Windows adapter state-machine checks with native APIs replaced, never host tasks."""

import copy
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.agent import windows_profile_sync as w
from apps.agent.profile_config import ISSUER, fingerprint, payload


def profile():
    return {
        "id": str(uuid4()),
        "profile_key": "standard-user",
        "display_name": "Standard",
        "account": "atomic-user",
        "expected_sid": "S-1-5-21-111-222-333-1001",
        "privilege": "standard",
        "logon_type": "batch",
        "enabled": True,
        "validated": False,
    }


def evidence(p):
    return {
        "expected_profile_id": p["id"],
        "expected_account_sid": p["expected_sid"],
        "actual_account_sid": p["expected_sid"],
        "actual_account_name": p["account"],
        "elevated": False,
        "admin_member": False,
        "admin_enabled": False,
        "integrity_level": "medium",
        "process_id": 123,
        "verified": True,
    }


@pytest.fixture
def local(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    keyfile = tmp_path / "public.pem"
    keyfile.write_bytes(public)
    state = tmp_path / "jobs"
    state.mkdir()
    secret = tmp_path / "credential"
    secret.write_bytes(b"unchanged-local-credential")
    config = {
        "actor_id": str(uuid4()),
        "hostname": "windows-fixture",
        "os": "windows",
        "api_url": "https://control.example.test",
        "state_root": str(state),
        "public_key_file": str(keyfile),
        "credential_file": str(secret),
        "profiles": [profile()],
    }
    configfile = tmp_path / "agent.json"
    configfile.write_text(json.dumps(config))
    monkeypatch.setattr(w, "protected", lambda path: None)
    monkeypatch.setattr(w, "restrict_acl", lambda *args: None)
    monkeypatch.setattr(w, "check_task_descriptor", lambda task: None)

    def signed(profiles=None, generation=1, **changes):
        target = payload({**config, "profiles": config["profiles"] if profiles is None else profiles})
        value = {
            "iss": ISSUER,
            "aud": config["actor_id"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 120,
            "jti": str(uuid4()),
            "generation": generation,
            "type": "profile-sync-v1",
            "payload": target,
            "payload_hash": fingerprint(target),
            **changes,
        }
        return jwt.encode(value, key, algorithm="RS256")

    return config, configfile, signed


def test_apply_addition_and_lost_ack_preserve_transport_and_do_not_reprobe(local, monkeypatch):
    config, path, signed = local
    added = {**profile(), "profile_key": "local-admin", "privilege": "elevated"}
    calls = []

    def validate(current, file, removed):
        calls.append((copy.deepcopy(current["profiles"]), removed))
        current["profiles"][0]["validated"] = True
        return {
            p["id"]: {
                "healthy": p["validated"],
                "identity": evidence(p) if p["validated"] else None,
                "error": "" if p["validated"] else "task_missing",
            }
            for p in current["profiles"]
        }

    monkeypatch.setattr(w, "validate_profiles", validate)
    token = signed([config["profiles"][0], added])
    updated, receipt = w.apply_manifest(config, path, token)
    assert receipt["result"]["error"] == ""
    assert len(updated["profiles"]) == 2 and calls[0][1] == []
    for key in ["actor_id", "api_url", "credential_file", "public_key_file"]:
        assert updated[key] == config[key]
    assert open(config["credential_file"], "rb").read() == b"unchanged-local-credential"
    assert w.apply_manifest(updated, path, token)[1]["result"] == receipt["result"]
    assert len(calls) == 1


def test_removal_survives_interrupted_cleanup_and_empty_profile_state(local, monkeypatch):
    config, path, signed = local
    calls = []

    def validate(current, file, removed):
        calls.append(copy.deepcopy(removed))
        if len(calls) == 1:
            raise RuntimeError("native task removal failed")
        return {}

    monkeypatch.setattr(w, "validate_profiles", validate)
    token = signed([])
    updated, receipt = w.apply_manifest(config, path, token)
    assert receipt["result"]["error"] == "apply_failed"
    assert updated["profiles"] == [] and updated["profile_sync_removed"] == config["profiles"]
    updated, receipt = w.apply_manifest(updated, path, token)
    assert receipt["result"]["error"] == "" and "profile_sync_removed" not in updated
    assert calls[0] == calls[1] == config["profiles"]


@pytest.mark.parametrize("mutation", ["signature", "actor", "active", "local_change"])
def test_rejects_untrusted_or_busy_configuration_before_application(local, monkeypatch, mutation):
    config, path, signed = local
    token = signed()
    if mutation == "signature":
        token = token[:-10] + "A" * 10
    elif mutation == "actor":
        token = signed(aud=str(uuid4()))
    elif mutation == "active":
        (path.parent / "jobs" / "active.json").write_text("{}")
    else:
        path.write_text(json.dumps({**config, "hostname": "changed"}))
    before = path.read_bytes()
    monkeypatch.setattr(w, "validate_profiles", lambda *args: pytest.fail("Must not probe"))
    with pytest.raises((ValueError, RuntimeError, jwt.PyJWTError)):
        w.apply_manifest(config, path, token)
    assert path.read_bytes() == before


def test_missing_folder_marks_profiles_unhealthy_without_creating_tasks(local, monkeypatch):
    config, path, _ = local
    monkeypatch.setattr(w, "task_folder", lambda: None)
    results = w.validate_profiles(config, path, [])
    assert results[config["profiles"][0]["id"]]["error"] == "task_missing"
    assert not config["profiles"][0]["validated"]


def test_native_scheduler_failure_is_not_treated_as_successful_removal(local, monkeypatch):
    config, path, _ = local
    monkeypatch.setattr(w, "task_folder", lambda: (_ for _ in ()).throw(RuntimeError("offline scheduler")))
    with pytest.raises(RuntimeError):
        w.validate_profiles(config, path, config["profiles"])


def task(p, path, probe=True):
    action = SimpleNamespace(
        Type=0, Path="C:/Python/python.exe", WorkingDirectory=str(path.parent), Arguments="probe"
    )
    principal = SimpleNamespace(UserId=p["expected_sid"], LogonType=1, RunLevel=0)
    return SimpleNamespace(
        Enabled=True,
        State=3,
        Definition=SimpleNamespace(
            Principal=principal, Actions=SimpleNamespace(Count=1, Item=lambda _: action)
        ),
    )


@pytest.mark.parametrize("mutation", [None, "elevation", "arguments", "executable", "sid"])
def test_task_identity_and_exact_fixed_action_are_checked(local, monkeypatch, mutation):
    config, path, _ = local
    p = config["profiles"][0]
    value = task(p, path)
    config["python_path"] = "C:/Python/python.exe"
    monkeypatch.setattr(w, "account_sid", lambda value: value)
    args = ["-I", "-m", "apps.agent.identity_probe", "--config", str(path), "--profile-id", p["id"]]
    monkeypatch.setattr(w, "split_arguments", lambda text: args)
    if mutation == "elevation":
        value.Definition.Principal.RunLevel = 1
    elif mutation == "arguments":
        args[2] = "apps.agent.task_wrapper"
    elif mutation == "executable":
        value.Definition.Actions.Item(1).Path = "other-python.exe"
    elif mutation == "sid":
        value.Definition.Principal.UserId = "S-1-5-18"
    folder = SimpleNamespace(GetTask=lambda name: value)
    if mutation:
        with pytest.raises(w.ProfileError):
            w.checked_task(folder, p, config, path, probe=True)
    else:
        assert w.checked_task(folder, p, config, path, probe=True) is value


def test_only_token_probe_task_runs_and_stale_evidence_is_removed(local, monkeypatch):
    config, path, _ = local
    p = config["profiles"][0]
    output = path.parent / "jobs" / p["id"] / "output" / "identity-probe.json"
    output.parent.mkdir(parents=True)
    output.write_text(json.dumps({"verified": True, "actual_account_sid": "stale"}))
    calls = []
    probe = SimpleNamespace(State=3, LastTaskResult=0, LastRunTime=0)

    def run(_):
        assert not output.exists()
        calls.append("identity-probe")
        probe.LastRunTime = 1
        output.write_text(json.dumps(evidence(p)))

    probe.Run = run
    monkeypatch.setattr(w, "account_sid", lambda account: p["expected_sid"])
    monkeypatch.setattr(
        w,
        "checked_task",
        lambda *args, probe=False: (
            probe_task if probe else SimpleNamespace(Run=lambda _: pytest.fail("Execution task must not run"))
        ),
    )
    probe_task = probe
    result = w.probe_profile(object(), p, config, path)
    assert result["verified"] and calls == ["identity-probe"]


@pytest.mark.parametrize("previous_result", [0x41303, 1])
def test_probe_waits_for_a_new_run_instead_of_rejecting_the_old_result(local, monkeypatch, previous_result):
    config, path, _ = local
    p = config["profiles"][0]
    output = Path(config["state_root"]) / p["id"] / "output" / "identity-probe.json"
    output.parent.mkdir(parents=True)
    probe = SimpleNamespace(State=3, LastTaskResult=previous_result, LastRunTime=0, Run=lambda _: None)
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds
        # Scheduler can acknowledge Run before publishing the new run/status.
        if now[0] >= 2:
            probe.LastRunTime = 1
            probe.LastTaskResult = 0
            output.write_text(json.dumps(evidence(p)))

    monkeypatch.setattr(w, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep))
    monkeypatch.setattr(w, "account_sid", lambda _: p["expected_sid"])
    monkeypatch.setattr(w, "checked_task", lambda *args, **kwargs: probe)
    assert w.probe_profile(object(), p, config, path)["verified"]
    assert now[0] >= 2


@pytest.mark.parametrize("starts", [False, True])
def test_probe_reports_the_windows_result_and_keeps_startup_wait_bounded(local, monkeypatch, starts):
    config, path, _ = local
    p = config["profiles"][0]
    (Path(config["state_root"]) / p["id"] / "output").mkdir(parents=True)
    probe = SimpleNamespace(State=3, LastTaskResult=0x41303, LastRunTime=0)
    now = [0.0]

    def run(_):
        if starts:
            probe.LastRunTime = 1
            probe.LastTaskResult = 1

    probe.Run = run
    monkeypatch.setattr(
        w,
        "time",
        SimpleNamespace(monotonic=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds)),
    )
    monkeypatch.setattr(w, "account_sid", lambda _: p["expected_sid"])
    monkeypatch.setattr(w, "checked_task", lambda *args, **kwargs: probe)
    with pytest.raises(w.ProfileError, match="^probe_failed$") as error:
        w.probe_profile(object(), p, config, path)
    assert f"last_result=0x{probe.LastTaskResult:08X}" in str(error.value.__cause__)
    if starts:
        assert now[0] == 0
    else:
        assert 25 <= now[0] < 25.2


def test_only_removed_profile_tasks_are_deleted(local, monkeypatch):
    config, path, _ = local
    old = config["profiles"][0]
    config["profiles"] = []
    deleted = []
    folder = SimpleNamespace(DeleteTask=lambda name, flags: deleted.append(name))
    monkeypatch.setattr(w, "task_folder", lambda: folder)
    monkeypatch.setattr(w, "checked_task", lambda *args, **kwargs: SimpleNamespace(State=3))
    assert w.validate_profiles(config, path, [old]) == {}
    assert deleted == [old["id"], old["id"] + "-identity"]


@pytest.mark.parametrize("mutation", [None, "owner", "null_dacl", "user_write", "delete_child"])
def test_native_descriptors_reject_untrusted_write_access(monkeypatch, mutation):
    import types

    monkeypatch.setitem(
        sys.modules, "win32security", types.SimpleNamespace(ConvertSidToStringSid=lambda sid: sid)
    )
    owner = "S-1-5-32-544" if mutation != "owner" else "S-1-5-21-111-222-333-1001"
    entries = [((0, 0), 0x10000000, "S-1-5-18"), ((0, 0), 0x1200A9, "S-1-5-32-545")]
    if mutation == "user_write":
        entries.append(((0, 0), 2, "S-1-5-32-545"))
    if mutation == "delete_child":
        entries.append(((0, 0), 0x40, "S-1-5-32-545"))
    acl = SimpleNamespace(GetAceCount=lambda: len(entries), GetAce=lambda index: entries[index])
    descriptor = SimpleNamespace(
        GetSecurityDescriptorOwner=lambda: owner,
        GetSecurityDescriptorDacl=lambda: None if mutation == "null_dacl" else acl,
    )
    if mutation:
        with pytest.raises(ValueError):
            w.check_descriptor(descriptor)
    else:
        w.check_descriptor(descriptor)


class NativeAutomationError(Exception):
    def __init__(self, outer, inner=None):
        self.hresult = outer
        self.excepinfo = None if inner is None else (0, "Task Scheduler", "failure", None, 0, inner)
        super().__init__(outer, "native failure", self.excepinfo, None)


@pytest.mark.parametrize(
    ("outer", "inner", "missing"),
    [
        (-2147024894, None, True),
        (-2147352567, -2147024894, True),
        (-2147352567, -2147024893, True),
        (-2147352567, -2147024891, False),
        (-2147024891, None, False),
    ],
)
def test_wrapped_scheduler_errors_preserve_access_denied(outer, inner, missing):
    assert w.missing_task(NativeAutomationError(outer, inner)) is missing


@pytest.mark.parametrize("inner", [-2147024894, -2147024891])
def test_wrapped_folder_error_distinguishes_absence_from_denied_access(local, monkeypatch, inner):
    import types

    error = NativeAutomationError(-2147352567, inner)

    def get_folder(name):
        raise error

    scheduler = SimpleNamespace(Connect=lambda: None, GetFolder=get_folder)
    client = types.ModuleType("win32com.client")
    client.Dispatch = lambda name: scheduler
    com = types.ModuleType("win32com")
    com.client = client
    monkeypatch.setitem(sys.modules, "pythoncom", SimpleNamespace(CoInitialize=lambda: None))
    monkeypatch.setitem(sys.modules, "win32com", com)
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    if inner == -2147024894:
        assert w.task_folder() is None
    else:
        with pytest.raises(RuntimeError):
            w.task_folder()


def test_wrapped_missing_profile_task_is_actionable(local):
    config, path, _ = local

    def get_task(name):
        raise NativeAutomationError(-2147352567, -2147024894)

    folder = SimpleNamespace(GetTask=get_task)
    with pytest.raises(w.ProfileError, match="task_missing"):
        w.checked_task(folder, config["profiles"][0], config, path)


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\netwo\AppData\Local\Python\python.exe",
        r"C:\Users\netwo\AppData\Local\Microsoft\WindowsApps\python.exe",
        r"C:\Users\another\Python\python.exe",
        r"C:\Python314\python.exee",
        r"python.exe",
    ],
)
def test_runtime_update_rejects_per_user_or_misspelled_python(path, monkeypatch):
    from apps.agent.packaging.update_windows import require_machine_python

    monkeypatch.delenv("USERPROFILE", raising=False)
    with pytest.raises(ValueError):
        require_machine_python(path)


@pytest.mark.parametrize("path", [r"C:\Program Files\Python314\python.exe", r"C:\Python314\python.exe"])
def test_runtime_update_accepts_all_users_python(path):
    from apps.agent.packaging.update_windows import require_machine_python

    require_machine_python(path)


def test_retired_tasks_can_be_removed_after_python_migration_but_never_validate(local, monkeypatch):
    config, path, _ = local
    p = config["profiles"][0]
    value = task(p, path)
    value.Definition.Actions.Item(1).Path = r"C:\Users\old\AppData\Local\Microsoft\WindowsApps\python.exee"
    config["python_path"] = r"C:\Program Files\Python314\python.exe"
    args = ["-I", "-m", "apps.agent.task_wrapper", "--config", str(path), "--profile-id", p["id"]]
    monkeypatch.setattr(w, "split_arguments", lambda text: args)
    monkeypatch.setattr(w, "account_sid", lambda sid: sid)
    folder = SimpleNamespace(GetTask=lambda name: value)
    with pytest.raises(w.ProfileError, match="task_mismatch"):
        w.checked_task(folder, p, config, path)
    assert w.checked_task(folder, p, config, path, enabled=False, for_removal=True) is value
    args[2] = "unrelated.task"
    with pytest.raises(w.ProfileError, match="task_mismatch"):
        w.checked_task(folder, p, config, path, enabled=False, for_removal=True)
