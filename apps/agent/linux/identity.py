"""Capture kernel UID/GID, capability and no-new-privileges evidence in the executor."""

import os
import sys
from pathlib import Path


def capture_identity(profile: dict) -> dict:
    if sys.platform != "linux":
        raise RuntimeError("Linux kernel identity inspection requires Linux")
    import pwd

    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    uid, euid, saved_uid, fsuid = map(int, status["Uid"].split())
    gid, egid, saved_gid, fsgid = map(int, status["Gid"].split())
    if (uid, uid) != (saved_uid, fsuid) or (gid, gid) != (saved_gid, fsgid):
        raise ValueError("Saved/filesystem identity differs from the real identity")
    return {
        "platform": "linux",
        "expected_profile_id": profile["id"],
        "expected_account_sid": profile["expected_sid"],
        "actual_account_sid": f"uid:{euid}",
        "actual_account_name": pwd.getpwuid(euid).pw_name,
        "uid": uid,
        "euid": euid,
        "gid": gid,
        "egid": egid,
        "groups": list(map(int, status["Groups"].split())),
        "capabilities": status["CapEff"].strip().lower(),
        "permitted_capabilities": status["CapPrm"].strip().lower(),
        "ambient_capabilities": status["CapAmb"].strip().lower(),
        "bounding_capabilities": status["CapBnd"].strip().lower(),
        "no_new_privileges": status["NoNewPrivs"].strip() == "1",
        "elevated": euid == 0,
        "process_id": os.getpid(),
        "verified": False,
    }


def validate_identity(identity: dict, profile: dict) -> dict:
    root = profile["privilege"] == "elevated"
    matches = (
        identity["actual_account_sid"] == profile["expected_sid"] == f"uid:{identity['uid']}"
        and identity["actual_account_name"] == profile["account"]
        and identity["uid"] == identity["euid"]
        and identity["gid"] == identity["egid"]
    )
    if root:
        matches = matches and identity["uid"] == 0 and identity["gid"] == 0
    else:
        matches = (
            matches
            and profile["privilege"] == "standard"
            and identity["uid"] > 0
            and identity["gid"] > 0
            and 0 not in identity["groups"]
            and identity["no_new_privileges"]
            and all(
                int(identity[k], 16) == 0
                for k in [
                    "capabilities",
                    "permitted_capabilities",
                    "ambient_capabilities",
                    "bounding_capabilities",
                ]
            )
        )
    if not matches:
        raise ValueError("Actual Linux kernel identity differs from the approved profile")
    return {**identity, "verified": True}
