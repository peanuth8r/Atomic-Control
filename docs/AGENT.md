# Windows agent and broker

`AtomicControlAgent` is a LocalSystem Python service with outbound verified HTTPS. Enrollment uses an actor-bound single-use token; subsequent transport uses its own rotating opaque machine credential, DPAPI-encrypted in a SYSTEM/Administrators-only secrets directory. The API stores credential digests. Profile metadata arrives in signed actor-bound generations and cannot redefine the selected identity through a job request.

## Fixed dispatch

For on-demand jobs, the service verifies a signed preparation assignment, downloads the approved bundle through the API and validates its manifest/files. Payload paths are protected against profile modification. The API rechecks readiness before issuing a separate execution grant.

Each profile has fixed password-backed execution and identity-probe Task Scheduler tasks. Actions bind only the installed Python/configuration and immutable profile ID. Jobs cannot supply another executable, account, shell path or arbitrary command. Input is protected and profile-readable; bounded output is isolated per profile/attempt.

The task wrapper independently checks signature, audience, snapshot, lease, fence, actual Windows token and exact definition. Standard users must have the expected SID, no administrator membership and medium integrity; elevated profiles need their exact SID, enabled administrator token and high integrity. The PowerShell child rechecks identity and module hash and invokes the selected technique/GUID with approved defaults.

The wrapper supplies Windows platform variables when running in Windows PowerShell 5.1 before importing Invoke-AtomicRedTeam. Strict mode remains enabled. Execute uses the fixed exit-code logger; check classifies reviewed prerequisite output; cleanup reports its separate process result. No `GetPrereqs`, arbitrary input overrides or prerequisite installation commands are invoked.

The service manages an attempt-specific Windows Job Object with kill-on-close containment and restricted selected-SID access. It renews leases and monitors deadlines, output bounds and cancellation/connectivity. A containment/termination state that cannot be verified holds the actor. This is a trusted-host execution boundary, not containment against a hostile administrator.

Pinned-checkout delivery is selectable. In that mode the runner additionally verifies a protected clean Git checkout at the exact approved revision/hash. These host-checkout checks do not require an on-demand actor to install the full catalog.

## Restart and uncertain outcomes

The broker writes an exclusive protected `jobs/active.json` journal before attempt preparation/dispatch. After termination it removes downloaded payload/output files, buffers evidence when needed and acknowledges workspace removal. It clears durable ownership only after the required receipts/reporting complete.

Restart recovery stops recorded tasks/processes and retries safe removal/reporting. It never replays execution. Expired execution leases become inconclusive; actor locks and uncertain journals remain until investigation. A lost result acknowledgement can leave local state even when the API holds a terminal result. Inspect both sides.

Verify processes and host effects, then record administrator reconciliation and archive only that attempt's journal before restarting. Do not clear journals or mark unknown outcomes successful to resume polling. Identical result resubmission is accepted; conflicting results are rejected. See [workspace recovery](ON_DEMAND_TEST_DELIVERY.md#recovery).

## Windows service diagnostics

Structured events go to **Event Viewer → Windows Logs → Application** through pywin32 and to standard output when available. `worker.error` carries a fixed worker stage, exception type and available numeric Windows/OS/process/HTTP status codes. `job.preparation_error` distinguishes assignment verification from preparation-journal writing. Exception messages, HTTP headers, grants and configuration contents are excluded. Logging failure does not stop recovery.

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Application'
  StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 300 |
  Where-Object { $_.ProviderName -match 'Python|AtomicControl' } |
  Select-Object TimeCreated, ProviderName, Message | Format-List
```

A heartbeat proves connectivity, not successful assignment validation or test execution. Use run evidence, the fixed failure stage, Task Scheduler events and host investigation together. See [execution troubleshooting](WINDOWS_EXECUTION_PREREQUISITES.md).

### Token clock differences

`ImmatureSignatureError` indicates an issued-at/not-before time ahead of the actor clock. The control plane backdates agent token `iat` by five seconds while preserving expiration, approval and lease deadlines. Signature, issuer/audience, not-before and expiration checks remain enabled. Keep server and actors synchronized with their trusted time sources.

```powershell
Start-Service W32Time
w32tm /resync /rediscover
w32tm /query /status
```

These commands use the configured Windows time source. Investigate larger drift; do not disable token validation. See [Microsoft's Windows Time tools](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings).

## Trust and validation

Protect the interpreter, wrappers, configuration, framework tree and dependencies from profile writes. The installer verifies pinned framework archives and the wrapper checks its configured manifest hash. Output is trusted host reporting, not tamper-proof attestation. Execution completion does not prove security-tool detection or host cleanup. Complete [platform validation](VALIDATION.md) for the actual Windows environment.
