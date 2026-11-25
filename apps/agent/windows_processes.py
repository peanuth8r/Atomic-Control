"""Broker-held Windows Job Object for an on-demand attempt's entire process tree."""

import time
from uuid import UUID


class JoinError(OSError):
    def __init__(self, stage, error):
        super().__init__("Windows process containment join failed")
        self.stage = stage
        self.winerror = getattr(error, "winerror", None)
        self.errno = getattr(error, "errno", None)


def name(attempt_id):
    return "Global\\AtomicControl-" + str(UUID(attempt_id))


def create(attempt_id, sid):
    import pywintypes
    import win32api
    import win32job
    import win32security

    descriptor = win32security.SECURITY_DESCRIPTOR()
    acl = win32security.ACL()
    for identity, access in [
        ("S-1-5-18", win32job.JOB_OBJECT_ALL_ACCESS),
        ("S-1-5-32-544", win32job.JOB_OBJECT_ALL_ACCESS),
        (sid, win32job.JOB_OBJECT_ASSIGN_PROCESS | win32job.JOB_OBJECT_QUERY),
    ]:
        acl.AddAccessAllowedAce(
            win32security.ACL_REVISION, access, win32security.ConvertStringSidToSid(identity)
        )
    descriptor.SetSecurityDescriptorDacl(1, acl, 0)
    # The broker runs as SYSTEM; its default object integrity can prevent a
    # medium-integrity profile from opening the object for process assignment,
    # even though that profile's SID is allowed by the DACL. Label this one
    # attempt's job medium while retaining the exact SID's limited rights.
    label = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;;NW;;;ME)", 1)
    descriptor.SetSecurityDescriptorSacl(1, label.GetSecurityDescriptorSacl(), 0)
    descriptor.SetSecurityDescriptorOwner(win32security.ConvertStringSidToSid("S-1-5-18"), 0)
    descriptor.SetSecurityDescriptorGroup(win32security.ConvertStringSidToSid("S-1-5-32-544"), 0)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    handle = win32job.CreateJobObject(attributes, name(attempt_id))
    try:
        if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS: never trust a pre-created object/ACL.
            raise RuntimeError("Attempt process containment already exists")
        limits = win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
        limits["BasicLimitInformation"]["LimitFlags"] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation, limits)
    except Exception:
        handle.Close()
        raise
    return handle


def join(attempt_id):
    import win32api
    import win32job

    try:
        handle = win32job.OpenJobObject(
            win32job.JOB_OBJECT_ASSIGN_PROCESS | win32job.JOB_OBJECT_QUERY, False, name(attempt_id)
        )
    except Exception as error:
        raise JoinError("open_process_containment", error) from error
    try:
        win32job.AssignProcessToJobObject(handle, win32api.GetCurrentProcess())
    except Exception as error:
        handle.Close()
        raise JoinError("assign_process_containment", error) from error
    return handle  # Caller holds this until process exit; descendants cannot break away.


def open_existing(attempt_id):
    import pywintypes
    import win32job

    try:
        return win32job.OpenJobObject(win32job.JOB_OBJECT_ALL_ACCESS, False, name(attempt_id))
    except pywintypes.error as exc:
        if exc.winerror == 2:
            return None
        raise


def terminate_and_verify(handle):
    import win32job

    if handle is None:
        raise RuntimeError("Process containment cannot be verified; reconciliation required")
    win32job.TerminateJobObject(handle, 1)
    deadline = time.monotonic() + 15
    while win32job.QueryInformationJobObject(handle, win32job.JobObjectBasicAccountingInformation)[
        "ActiveProcesses"
    ]:
        if time.monotonic() >= deadline:
            raise RuntimeError("Execution process tree is still active")
        time.sleep(0.1)
