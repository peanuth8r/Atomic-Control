# Repair Windows profile validation after a Python path mismatch

Use this procedure when the installed agent and its fixed scheduled tasks reference different Python executables, or the agent was installed using a per-user Python. It preserves actor enrollment and credentials. Finish active work and reconcile any uncertain execution before stopping the service.

## Install Python for all users

Use the traditional 64-bit Windows installer for a supported Python version from [Python's Windows downloads](https://www.python.org/downloads/windows/). Choose **Customize installation**, keep pip enabled, and select **Install for all users**. Use a protected machine directory such as `C:\Program Files\Python314`. See the [official Windows installer options](https://docs.python.org/3.14/using/windows.html#the-full-installer-deprecated).

Avoid user-profile, AppData and WindowsApps paths. A per-user Python can be outside a virtual environment and still be unsuitable for a service and separate test account. Keep the existing Python until the repaired service and profile are verified.

```powershell
& 'C:\Program Files\Python313\python.exe' --version
```

## Update the existing enrollment

As an administrator, choose **Actors → host → Download agent update**, generate a fresh configuration-only ZIP, verify its checksum against the UI, and extract it. Do not delete/recreate the actor or request another enrollment token.

From Administrator PowerShell in the extracted `AtomicControlAgent` directory, using the actual all-users Python path:

```powershell
$ErrorActionPreference = 'Stop'
$python = 'C:\Program Files\Python313\python.exe'
Stop-Service AtomicControlAgent

# The new interpreter needs the bundled dependencies before running the updater.
& $python -I -m pip install -r .\runtime\requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; leave the service stopped.' }

& $python -I .\Update-Agent.py --enable-profile-sync --check-only
if ($LASTEXITCODE -ne 0) { throw 'Signed update preflight failed; leave the service stopped.' }

& $python -I .\Update-Agent.py --enable-profile-sync
if ($LASTEXITCODE -ne 0) { throw 'Runtime update failed; leave the service stopped.' }
```

The updater validates the signed archive against the already pinned key, installs the runtime under the selected interpreter, refreshes pywin32 and the stopped Windows service registration, and updates the stored Python path. Actor ID, profiles, encrypted machine credential and signing key are retained. It does not start the service or run a test.

## Recreate the fixed tasks and validate

Still in that extracted directory:

```powershell
.\runtime\scripts\provision-profiles.ps1 `
  -ConfigFile 'C:\ProgramData\AtomicControl\agent.json' `
  -PythonPath $python `
  -InstallRoot 'C:\Program Files\AtomicControl\runtime'

Start-Service AtomicControlAgent
Get-Service AtomicControlAgent
```

Enter the execution account password only in the Windows prompt. The provisioning helper requires the exact configured Python, verifies that it exists and is an all-users installation, and recreates the fixed execution and token-probe tasks. Misspelled paths such as `python.exee` are rejected before tasks are registered.

Open actor details and choose **Retry validation**. The agent checks task definitions, permissions and the actual SID/token before reporting profile health. Standard-user accounts must not belong to Administrators; elevated profiles need an administrator token. The account's name does not determine its privilege. No Atomic test runs during this validation.

Deleted-profile tasks are removed only after confirming protected ownership, profile SID/privilege and exact fixed module/configuration/profile arguments. Execution validation requires the configured Python path; cleanup of a deleted profile can recognize a verified task bound to another interpreter. Local accounts and history remain intact.

If validation still fails, inspect the reported profile error and agent service output. Do not set `validated=true` manually or clear an execution journal to bypass validation. See [automatic Windows profiles](EXECUTION_SETUP.md#windows-automatic-profiles).

## A probe task never starts

Task Scheduler's `0x00041303` result means the task has never run; it is not the probe's process exit code. Check **Event Viewer → Applications and Services Logs → Microsoft → Windows → TaskScheduler → Operational**. Enable the log if needed, then choose **Retry validation** and inspect events for the current profile's `-identity` task.

Events 101/104 reporting `2147943785` (`0x80070569`, `ERROR_LOGON_TYPE_NOT_GRANTED`) mean Windows denied the batch logon. Open `secpol.msc` as an administrator, go to **Local Policies → User Rights Assignment**, and add the specific execution account to **Log on as a batch job**. Check **Deny log on as a batch job** for the account or its groups: a denial overrides an allow. If domain policy controls these settings, change the applicable policy rather than a temporary local override. See [Microsoft's batch-logon policy documentation](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/log-on-as-a-batch-job).

Keep a standard-user execution account outside Administrators. Retry validation after the policy change; the next batch logon uses the new rights, without recreating the actor or reinstalling Python. This rights change is performed locally by the administrator; the agent does not grant it automatically.

Identity probes wait up to 25 seconds for a fresh task run/evidence. Diagnostic failures include the last Windows result and task state. A real policy, credential or task-definition failure blocks profile health.
