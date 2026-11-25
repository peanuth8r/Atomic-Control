"""Apply signed Windows profile metadata and run only fixed identity-probe tasks.

Passwords stay in Task Scheduler. Missing tasks require local provisioning; this
module never registers credentials, launches an Atomic task, or creates accounts.
"""

import ctypes
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path
from uuid import uuid4

from .execution_broker import restrict_acl
from .identity_validation import validate_identity
from .job_client import heartbeat_payload
from .profile_config import fingerprint, payload, verify_manifest


class ProfileError(ValueError):
    pass


def no_reparse(path):
    if not path.is_absolute():
        raise ValueError("Use an absolute Windows path")
    for entry in [*reversed(path.parents), path]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Profile paths cannot contain reparse points")


def protected(path):
    import win32security

    no_reparse(path)
    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    check_descriptor(descriptor)


def check_descriptor(descriptor):
    import win32security

    trusted = {"S-1-5-18", "S-1-5-32-544"}
    if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in trusted:
        raise ValueError("Profile configuration must be owned by SYSTEM or Administrators")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise ValueError("Unprotected profile configuration")
    write_mask = 0x40000000 | 0x10000000 | 0x10000 | 0x40000 | 0x80000 | 0x2 | 0x4 | 0x10 | 0x40 | 0x100
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if ace[0][0] in {0, 5, 9, 11} and not ace[0][1] & 0x8:
            if ace[1] & write_mask and win32security.ConvertSidToStringSid(ace[-1]) not in trusted:
                raise ValueError("Untrusted account can modify profile configuration")


def write_config(path, value, readable=True):
    protected(path.parent)
    if path.exists():
        protected(path)
    temp = path.parent / (".profile-sync-" + uuid4().hex + ".json")
    try:
        with temp.open("x") as handle:
            restrict_acl(temp, "S-1-5-32-545" if readable else None)
            json.dump(value, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def split_arguments(arguments):
    from ctypes import wintypes

    shell = ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    count = ctypes.c_int()
    pointer = shell.CommandLineToArgvW("python.exe " + arguments, ctypes.byref(count))
    if not pointer:
        raise ValueError("Invalid task arguments")
    try:
        return [pointer[index] for index in range(1, count.value)]
    finally:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(pointer)


def account_sid(account):
    import win32security

    if account.startswith("S-1-"):
        return account
    try:
        return win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, account)[0])
    except Exception as error:
        raise ProfileError("account_missing") from error


def check_task_descriptor(task):
    import win32security

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        task.GetSecurityDescriptor(5), 1
    )
    check_descriptor(descriptor)


def missing_task(error):
    """COM automation wraps Win32 errors inside DISP_E_EXCEPTION's EXCEPINFO."""
    missing = {0x80070002, 0x80070003}
    code = getattr(error, "hresult", None)
    if code is None and error.args and isinstance(error.args[0], int):
        code = error.args[0]
    if not isinstance(code, int):
        return False
    code &= 0xFFFFFFFF
    if code in missing:
        return True
    if code != 0x80020009:
        return False
    info = getattr(error, "excepinfo", None)
    if info is None and len(error.args) > 2:
        info = error.args[2]
    return (
        isinstance(info, (tuple, list))
        and len(info) >= 6
        and isinstance(info[5], int)
        and info[5] & 0xFFFFFFFF in missing
    )


def checked_task(folder, profile, config, config_file, probe=False, enabled=True, for_removal=False):
    name = profile["id"] + ("-identity" if probe else "")
    try:
        task = folder.GetTask(name)
    except Exception as error:
        if missing_task(error):
            raise ProfileError("task_missing") from error
        raise RuntimeError("Cannot inspect the scheduled task") from error
    try:
        check_task_descriptor(task)
    except ValueError as error:
        raise ProfileError("task_mismatch") from error
    definition = task.Definition
    principal = definition.Principal
    if (
        account_sid(principal.UserId) != profile["expected_sid"]
        or principal.LogonType != 1
        or principal.RunLevel != int(profile["privilege"] == "elevated")
    ):
        raise ProfileError("task_mismatch")
    if definition.Actions.Count != 1 or definition.Actions.Item(1).Type != 0:
        raise ProfileError("task_mismatch")
    action = definition.Actions.Item(1)
    module = "apps.agent.identity_probe" if probe else "apps.agent.task_wrapper"
    arguments = split_arguments(action.Arguments)
    if (
        (
            not for_removal
            and os.path.normcase(os.path.abspath(action.Path))
            != os.path.normcase(os.path.abspath(config.get("python_path", sys.executable)))
        )
        or len(arguments) != 7
        or arguments[:4] != ["-I", "-m", module, "--config"]
        or os.path.normcase(os.path.abspath(arguments[4])) != os.path.normcase(os.path.abspath(config_file))
        or arguments[5:] != ["--profile-id", profile["id"]]
    ):
        raise ProfileError("task_mismatch")
    if enabled and not task.Enabled:
        raise ProfileError("task_mismatch")
    if not for_removal:
        protected(Path(action.Path))
        protected(Path(action.WorkingDirectory))
    return task


def task_folder():
    import pythoncom
    import win32com.client

    pythoncom.CoInitialize()
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        try:
            folder = scheduler.GetFolder("\\AtomicControl")
            check_task_descriptor(folder)
            return folder
        except Exception as error:
            if missing_task(error):
                return None
            raise
    except Exception as error:
        raise RuntimeError("Cannot connect to the protected task folder") from error


def probe_profile(folder, profile, config, config_file):
    if account_sid(profile["account"]) != profile["expected_sid"]:
        raise ProfileError("identity_mismatch")
    checked_task(folder, profile, config, config_file)
    task = checked_task(folder, profile, config, config_file, probe=True)
    if task.State in {2, 4}:
        raise ProfileError("probe_failed")
    output = Path(config["state_root"]) / profile["id"] / "output" / "identity-probe.json"
    no_reparse(output.parent)
    if output.exists():
        no_reparse(output)
        output.unlink()
    previous_run = task.LastRunTime
    started = time.monotonic()

    def failed(reason):
        result = int(task.LastTaskResult) & 0xFFFFFFFF
        raise ProfileError("probe_failed") from RuntimeError(
            f"{reason}; task_state={int(task.State)}; last_result=0x{result:08X}"
        )

    try:
        task.Run(None)  # Always the fixed token-only probe; never the execution wrapper.
        while time.monotonic() - started < 25:
            if task.State not in {2, 4}:
                # LastTaskResult belongs to the previous run until Scheduler
                # actually starts this request. In particular, 0x41303 means
                # "never run", not that the new probe exited with an error.
                current_run = task.LastRunTime != previous_run
                result = int(task.LastTaskResult) & 0xFFFFFFFF
                scheduler_status = 0x41300 <= result <= 0x413FF
                if output.exists():
                    no_reparse(output)
                    if output.stat().st_size > 65536:
                        failed("Identity probe output exceeded the size limit")
                    if result == 0:
                        evidence = json.loads(output.read_text())
                        if (
                            evidence.get("expected_profile_id") != profile["id"]
                            or evidence.get("expected_account_sid") != profile["expected_sid"]
                        ):
                            raise ProfileError("identity_mismatch")
                        try:
                            return validate_identity(evidence, profile)
                        except (ValueError, RuntimeError, KeyError) as error:
                            raise ProfileError("identity_mismatch") from error
                if current_run and result != 0 and not scheduler_status:
                    failed("Identity probe returned a failure result")
            time.sleep(0.1)
        failed("Identity probe did not complete within 25 seconds")
    finally:
        if task.State in {2, 4}:
            task.Stop(0)
            deadline = time.monotonic() + 5
            while task.State in {2, 4} and time.monotonic() < deadline:
                time.sleep(0.1)
            if task.State in {2, 4}:
                raise RuntimeError("Identity probe termination is uncertain")


def validate_profiles(config, config_file, removed):
    results = {}
    folder = task_folder()
    for old in removed if folder is not None else []:
        for probe in [False, True]:
            try:
                # Retired tasks can still point to a previous Python installation.
                # Require protected ownership, SID/privilege and exact fixed
                # module/config/profile arguments; never run their executable.
                task = checked_task(
                    folder, old, config, config_file, probe=probe, enabled=False, for_removal=True
                )
            except ProfileError as error:
                if str(error) == "task_missing":
                    continue
                raise RuntimeError("Removed profile task could not be verified") from error
            if task.State in {2, 4}:
                raise RuntimeError("Cannot remove an active profile task")
            folder.DeleteTask(old["id"] + ("-identity" if probe else ""), 0)
    for profile in config["profiles"]:
        key = profile["id"]
        profile["validated"] = False
        results[key] = {"healthy": False, "identity": None, "error": "disabled"}
        if not profile["enabled"]:
            continue
        try:
            if folder is None:
                raise ProfileError("task_missing")
            evidence = probe_profile(folder, profile, config, config_file)
            profile["validated"] = True
            results[key] = {"healthy": True, "identity": evidence, "error": ""}
        except RuntimeError:
            raise
        except Exception as error:
            code = str(error) if isinstance(error, ProfileError) else "probe_failed"
            results[key] = {"healthy": False, "identity": None, "error": code}
    return results


def apply_manifest(config, config_file, token):
    protected(config_file)
    protected(Path(config["public_key_file"]))
    claims = verify_manifest(token, config, Path(config["public_key_file"]).read_text())
    journal = Path(config["state_root"]) / "active.json"
    if journal.exists() or journal.is_symlink():
        raise RuntimeError("Unreconciled execution prevents profile updates")
    current = json.loads(config_file.read_text())
    if current != config:
        raise RuntimeError("Local configuration changed; restart before profile updates")
    response = {
        "generation": claims["generation"],
        "payload_hash": claims["payload_hash"],
        "results": {},
        "error": "",
    }
    try:
        if (
            current.get("profile_sync_generation") == claims["generation"]
            and "profile_validation_results" in current
        ):
            if fingerprint(payload(current)) != claims["payload_hash"]:
                raise ValueError("Applied profile metadata changed")
            response["results"] = current["profile_validation_results"]
        else:
            if current.get("profile_sync_generation") != claims["generation"]:
                backup = config_file.parent / ("agent.before-profile-sync-" + uuid4().hex + ".json")
                write_config(backup, current, readable=False)
                target_ids = {p["id"] for p in claims["payload"]["profiles"]}
                removed = {
                    p["id"]: p
                    for p in current.get("profile_sync_removed", []) + current["profiles"]
                    if p["id"] not in target_ids
                }
                current.update(
                    profiles=[{**p, "validated": False} for p in claims["payload"]["profiles"]],
                    profile_sync_generation=claims["generation"],
                    profile_sync_hash=claims["payload_hash"],
                    profile_sync_removed=list(removed.values()),
                )
                current.pop("profile_validation_results", None)
                write_config(config_file, current)
            response["results"] = validate_profiles(
                current, config_file, current.get("profile_sync_removed", [])
            )
            current["profile_validation_results"] = response["results"]
            current.pop("profile_sync_removed", None)
            write_config(config_file, current)
    except Exception:
        response["error"] = "apply_failed"
        current = json.loads(config_file.read_text())
    return current, {"id": claims["jti"], "result": response}


def synchronize(config, config_file, client):
    answer = client.post("agents/profile-sync/poll")
    if not answer.get("manifest"):
        return config
    stop = threading.Event()

    def keep_alive():
        while not stop.wait(15):
            try:
                client.post("agents/heartbeat", heartbeat_payload(config))
            except Exception:
                pass

    thread = threading.Thread(target=keep_alive, daemon=True)
    thread.start()
    try:
        updated, receipt = apply_manifest(config, config_file, answer["manifest"])
    finally:
        stop.set()
        thread.join(timeout=21)
    client.post(f"agents/profile-sync/{receipt['id']}/result", receipt["result"])
    client.post("agents/heartbeat", heartbeat_payload(updated))
    return updated
