"""Containment security contracts with native Windows APIs replaced."""

import sys
from types import SimpleNamespace

import pytest

from apps.agent import windows_processes as jobs

ATTEMPT = "11111111-1111-4111-8111-111111111111"
PROFILE_SID = "S-1-5-21-1-2-3-1001"


@pytest.fixture
def native(monkeypatch):
    state = {"last_error": 0, "closed": False, "fail": ""}

    class Descriptor:
        def SetSecurityDescriptorDacl(self, present, acl, defaulted):
            state["dacl"] = (present, acl.aces, defaulted)

        def SetSecurityDescriptorSacl(self, present, acl, defaulted):
            state["sacl"] = (present, acl, defaulted)

        def SetSecurityDescriptorOwner(self, sid, defaulted):
            state["owner"] = sid

        def SetSecurityDescriptorGroup(self, sid, defaulted):
            state["group"] = sid

    class ACL:
        def __init__(self):
            self.aces = []

        def AddAccessAllowedAce(self, revision, access, sid):
            self.aces.append((access, sid))

    handle = SimpleNamespace(Close=lambda: state.update(closed=True))
    state["handle"] = handle

    def create(attributes, name):
        state["name"] = name
        state["descriptor"] = attributes.SECURITY_DESCRIPTOR
        return handle

    def fail_if(operation):
        if state["fail"] == operation:
            error = PermissionError(13, "private native error text")
            error.winerror = 5
            raise error

    def open_job(access, inherit, name):
        state["open"] = (access, inherit, name)
        fail_if("open")
        return handle

    def assign(job, process):
        state["assigned"] = (job, process)
        fail_if("assign")

    def set_limits(job, info, limits):
        fail_if("limits")
        state["limits"] = limits

    security = SimpleNamespace(
        SECURITY_DESCRIPTOR=Descriptor,
        ACL=ACL,
        ACL_REVISION=2,
        ConvertStringSidToSid=lambda text: text,
        ConvertStringSecurityDescriptorToSecurityDescriptor=lambda text, revision: SimpleNamespace(
            GetSecurityDescriptorSacl=lambda: text
        ),
    )
    api = SimpleNamespace(GetLastError=lambda: state["last_error"], GetCurrentProcess=lambda: "current")
    sdk = SimpleNamespace(
        JOB_OBJECT_ALL_ACCESS=0x1F001F,
        JOB_OBJECT_ASSIGN_PROCESS=1,
        JOB_OBJECT_QUERY=4,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE=0x2000,
        JobObjectExtendedLimitInformation=9,
        CreateJobObject=create,
        OpenJobObject=open_job,
        AssignProcessToJobObject=assign,
        QueryInformationJobObject=lambda *args: {"BasicLimitInformation": {"LimitFlags": 0}},
        SetInformationJobObject=set_limits,
    )
    for module, value in {
        "win32api": api,
        "win32job": sdk,
        "win32security": security,
        "pywintypes": SimpleNamespace(SECURITY_ATTRIBUTES=SimpleNamespace),
    }.items():
        monkeypatch.setitem(sys.modules, module, value)
    return state


def test_standard_profile_job_has_medium_label_and_only_limited_profile_access(native):
    assert jobs.create(ATTEMPT, PROFILE_SID) is native["handle"]
    assert native["owner"] == "S-1-5-18" and native["group"] == "S-1-5-32-544"
    assert native["sacl"] == (1, "S:(ML;;NW;;;ME)", 0)
    assert native["dacl"] == (
        1,
        [(0x1F001F, "S-1-5-18"), (0x1F001F, "S-1-5-32-544"), (5, PROFILE_SID)],
        0,
    )
    assert native["name"] == "Global\\AtomicControl-" + ATTEMPT
    assert native["limits"]["BasicLimitInformation"]["LimitFlags"] == 0x2000
    assert not native["closed"]


@pytest.mark.parametrize("failure", ["collision", "limits"])
def test_failed_creation_closes_the_handle_and_never_reuses_existing_jobs(native, failure):
    if failure == "collision":
        native["last_error"] = 183
    else:
        native["fail"] = failure
    with pytest.raises((RuntimeError, OSError)):
        jobs.create(ATTEMPT, PROFILE_SID)
    assert native["closed"]


def test_profile_opens_only_assign_and_query_rights_and_joins_its_own_process(native):
    assert jobs.join(ATTEMPT) is native["handle"]
    assert native["open"] == (5, False, "Global\\AtomicControl-" + ATTEMPT)
    assert native["assigned"] == (native["handle"], "current")
    assert not native["closed"]


@pytest.mark.parametrize("operation", ["open", "assign"])
def test_join_failure_identifies_the_native_operation_and_releases_unused_handles(native, operation):
    native["fail"] = operation
    with pytest.raises(jobs.JoinError) as failure:
        jobs.join(ATTEMPT)
    assert failure.value.stage == operation + "_process_containment"
    assert failure.value.winerror == 5 and failure.value.errno == 13
    assert "private native error text" not in str(failure.value)
    assert native["closed"] == (operation == "assign")


def test_invalid_attempt_id_cannot_select_an_arbitrary_named_object():
    with pytest.raises(ValueError):
        jobs.name("arbitrary-object")
