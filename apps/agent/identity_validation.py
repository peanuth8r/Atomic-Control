"""Read the process token, including deny-only administrator membership.

No account-name inference, IsUserAnAdmin shortcut, or self-reported identity.
"""

import ctypes
import os
from ctypes import wintypes


class IdentityMismatch(RuntimeError):
    pass


def capture_identity(profile_id: str, expected_sid: str) -> dict:
    if os.name != "nt":
        raise RuntimeError("Windows token inspection requires Windows")
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
        sid_text = win32security.ConvertSidToStringSid(sid)
        account, domain, _ = win32security.LookupAccountSid(None, sid)
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
        admin_member = any(
            win32security.ConvertSidToStringSid(group) == "S-1-5-32-544" for group, _ in groups
        )
        admin_enabled = any(
            win32security.ConvertSidToStringSid(group) == "S-1-5-32-544"
            and attributes & 4
            and not attributes & 16
            for group, attributes in groups
        )
        privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
        enabled_privileges = [
            win32security.LookupPrivilegeName(None, luid) for luid, attributes in privileges if attributes & 2
        ]
        elevated = bool(win32security.GetTokenInformation(token, win32security.TokenElevation))
        # PyWin32's integrity-level support varies; use GetTokenInformation directly.
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
        advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
        advapi.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        advapi.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        advapi.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(int(token), 25, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(int(token), 25, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        integrity_sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        count = advapi.GetSidSubAuthorityCount(integrity_sid)[0]
        rid = advapi.GetSidSubAuthority(integrity_sid, count - 1)[0]
        integrity = (
            "system" if rid >= 16384 else "high" if rid >= 12288 else "medium" if rid >= 8192 else "low"
        )
        stats = win32security.GetTokenInformation(token, win32security.TokenStatistics)
        return {
            "expected_profile_id": profile_id,
            "expected_account_sid": expected_sid,
            "actual_account_sid": sid_text,
            "actual_account_name": domain + "\\" + account,
            "logon_session_id": str(stats.get("AuthenticationId")),
            "elevated": elevated,
            "admin_member": admin_member,
            "admin_enabled": bool(admin_enabled),
            "enabled_privileges": enabled_privileges,
            "integrity_level": integrity,
            "process_id": os.getpid(),
            "verified": False,
        }
    finally:
        token.Close()


def validate_identity(identity: dict, profile: dict) -> dict:
    matches = identity["actual_account_sid"] == profile["expected_sid"]
    if profile["privilege"] == "standard":
        matches = (
            matches
            and not identity["elevated"]
            and not identity["admin_member"]
            and identity["integrity_level"] == "medium"
        )
    elif profile["privilege"] == "elevated":
        matches = (
            matches
            and identity["elevated"]
            and identity["admin_member"]
            and identity.get("admin_enabled", False)
            and identity["integrity_level"] == "high"
        )
    else:
        matches = False
    if not matches:
        raise IdentityMismatch("Actual Windows token differs from approved profile")
    return {**identity, "verified": True}
