# Windows execution prerequisites and troubleshooting

The Windows enrollment installer automatically installs/verifies Invoke-AtomicRedTeam and its YAML dependency before enrollment or service startup. On-demand jobs supply selected test files. Local execution accounts, fixed tasks, batch-logon rights and per-test external software remain separately provisioned.

## Framework installation

Generate/verify an enrollment ZIP and run it from Administrator Windows PowerShell 5.1 with protected all-users Python 3.12+:

```powershell
.\Install-Agent.ps1 -PythonPath 'C:\Program Files\Python313\python.exe' -StartService
```

Use the actual Python path. Setup verifies package/HTTPS, installs dependencies and prepares the real module path/hash in protected configuration before consuming enrollment. Matching installed files are verified/reused; differing files are preserved and setup stops. No Atomic tests, catalog payloads or per-test prerequisite commands run during on-demand setup.

## Verify or repair an enrolled actor

Finish/reconcile work and download a fresh configuration-only ZIP for the same actor. Verify/extract it. Use the [signed runtime update](EXECUTION_SETUP.md#windows-automatic-profiles) when updating agent code. With the service stopped, the package also provides this framework maintenance helper:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    Stop-Service AtomicControlAgent
    .\runtime\scripts\install-windows-execution-prerequisites.ps1
    Start-Service AtomicControlAgent
}
```

Initial installation calls the helper automatically. A runtime-only update needs no helper when framework paths/hashes already verify. The helper backs up protected configuration and changes only module path/hash; credentials, profiles, actor ID and signing key stay intact. It supports `-WhatIf` and refuses active/uncertain work. Per-user Python requires [interpreter/task-path repair](WINDOWS_PROFILE_REPAIR.md).

The framework pin is official revision `8af478bb9e4637df568ac1e596553b025b16cd1b`, installed under `C:\Program Files\AtomicControl\Invoke-AtomicRedTeam`. Source ZIP SHA-256 is `778489daf0a961478ff2716e556958817e22d29962d717b200b3d2b21eafb281`; manifest SHA-256 is `3ec05509a96193aa9e09cb9f2a37f68956e27edffbc851eecf9ebb458e23b513`. See [pinned source](https://github.com/redcanaryco/invoke-atomicredteam/tree/8af478bb9e4637df568ac1e596553b025b16cd1b).

The helper installs [powershell-yaml 0.4.12](https://www.powershellgallery.com/packages/powershell-yaml/0.4.12) for all users under `Program Files\WindowsPowerShell\Modules`; package SHA-256 is `d4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810`. Download is direct verified HTTPS without NuGet bootstrap or repository-trust changes. Verified/protected staging is published atomically. Source pins establish reproducibility, not a complete security audit.

## Diagnose execution failures

Inspect result status/output, [Application service events](AGENT.md#windows-service-diagnostics) and Task Scheduler Operational events together. Scheduler events 100/200 establish action start and 102/201 establish completion, not Atomic success. A missing result requires investigation; preserve uncertain state until host verification/reconciliation.

Initialization failures record fixed stages/types and numeric error codes. Missing framework paths report `verify_invoke_module_path`; an invalid pin reports `verify_invoke_module_pin`. Failures after an uncertain process-launch attempt remain inconclusive. Raw exception/configuration text is excluded from structured worker diagnostics.

### Process containment access denied

`open_process_containment` and `assign_process_containment` distinguish opening the broker's Job Object from joining it. An access-denied code requires investigation of the operation, object permissions and token integrity. The broker gives its per-attempt object a medium integrity label, SYSTEM/Administrators control and limited assignment/query access for the selected SID. Kill-on-close remains enabled. Do not weaken profile privilege or containment ACLs to suppress the failure. See [Windows integrity control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).

### Undefined IsLinux or IsMacOS during module import

Windows PowerShell 5.1 lacks Core platform variables. The fixed wrapper initializes Windows values before module import in the job process, preserves Core's native variables and retains strict mode/identity/hash checks. An undefined-variable import error calls for a configuration-preserving runtime update. Setting variables in an interactive console does not change the task's separate process.

### Empty input arguments rejected during YAML parsing

`'atomic_tests[0].input_arguments' must have at least one entry` identifies a cached YAML with `input_arguments: {}`. The control plane omits this optional field for input-free tests. In **Test Catalog**, retain the intended risk/profiles and click **Approve test** again to replace the cached file plan, then submit a new run. Historical plans/results stay intact. No agent update or reinstall is required for this serialization issue.

### Desktop-dependent tests

Password-backed tasks run noninteractively. Tests requiring a signed-in desktop, screen capture or mouse interaction are outside the supported batch execution model. Account/module health alone cannot establish desktop access. Do not change the fixed task logon type manually. See [task logon modes](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).

## WMI-dependent tests

Inspect the selected command's required tools. A definition invoking `wmic.exe` cannot work when that executable is absent, even with a healthy framework/profile. Use a separately reviewed/approved WMI/CIM or Windows PowerShell variant supported by the target OS. Execution-framework setup does not install every operating-system tool or approve alternative tests.
