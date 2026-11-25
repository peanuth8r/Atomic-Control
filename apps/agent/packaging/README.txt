WINDOWS AGENT PACKAGE

This ZIP contains allowlisted source, installers, actor configuration, dependency
requirements and fixed provisioning helpers. It embeds no Python interpreter,
wheels, server private key, account passwords or Atomic test payloads.

INSTALLATION
1. Verify the ZIP SHA-256 against the trusted HTTPS UI and extract it privately
   on the exact named actor. Install before the enrollment expiry above and in
   bootstrap.json; default 60 minutes is configurable for future issuance in Settings.
2. Install protected all-users Python 3.12+, accessible to LocalSystem and the
   execution accounts. Do not use per-user/AppData/WindowsApps Python.
3. In Administrator Windows PowerShell 5.1 in this package directory, run:
     .\Install-Agent.ps1 -PythonPath 'C:\Program Files\Python313\python.exe' -StartService
   Substitute the actual protected Python path and follow local script policy.
4. Register existing local execution-account SIDs in Actors -> Execution profiles.
   Signed metadata synchronizes while idle. Grant intended accounts Log on as a
   batch job locally; applicable deny policy overrides the allow. Provision tasks:
     .\runtime\scripts\provision-profiles.ps1 -ConfigFile 'C:\ProgramData\AtomicControl\agent.json' -PythonPath 'C:\Program Files\Python313\python.exe' -InstallRoot 'C:\Program Files\AtomicControl\runtime'
   Enter passwords only in the local Windows prompt. Standard accounts cannot be
   Administrators; elevated profiles require their exact elevated high-integrity token.
   Choose Retry validation after provisioning. Do not set validated=true manually.

Setup verifies package/hostname/token, imports the explicit bundled public CA into
LocalMachine\Root when supplied, and verifies HTTPS before enrollment. Compare
its fingerprint with the trusted UI. -SkipCATrust uses separately managed trust;
verified HTTPS is still required. CA trust remains after failure/uninstall.

The installer installs Python dependencies, including pywin32>=311, and automatically
installs/verifies pinned Invoke-AtomicRedTeam plus powershell-yaml before enrollment.
It records module path/hash in protected configuration, stores the machine credential
with DPAPI and registers AtomicControlAgent stopped. -StartService starts it only
after successful setup. Setup grants no account rights and runs no Atomic tests.

Dependency sources must be reachable: the approved Python package source, GitHub
framework archive and PowerShell Gallery YAML package. Framework archives are
checksum verified and installed for all users. No NuGet bootstrap or repository-trust
prompt is needed. Per-test external tools remain separately provisioned.

DELIVERY
On demand is the default: Run/Queue packages the approved test and declared files
automatically; the actor downloads only that attempt and removes its files afterward.
No Git or full local catalog is required. File removal does not undo test effects;
test cleanup is a separate authorized action.

Pinned checkout is selectable. It additionally needs machine-wide Git and a selected
imported commit. Before enrollment, setup fetches/verifies the exact official source,
protects its clean checkout and records a receipt. Dirty/different files are retained
and refused. Catalog installation does not approve definitions or execute tests.

CONFIGURATION-ONLY RUNTIME UPDATE
Finish/reconcile active work. Use a fresh ZIP for the same actor and verify its hash.
From Administrator PowerShell, with the actual all-users Python:
  & {
      $ErrorActionPreference = 'Stop'
      $python = 'C:\Program Files\Python313\python.exe'
      Stop-Service AtomicControlAgent
      & $python -I .\Update-Agent.py --enable-on-demand --check-only
      if ($LASTEXITCODE -ne 0) { throw 'Preflight failed; leave service stopped.' }
      & $python -I .\Update-Agent.py --enable-on-demand
      if ($LASTEXITCODE -ne 0) { throw 'Update failed; leave service stopped.' }
      Start-Service AtomicControlAgent
  }
Omit --enable-on-demand for checkout delivery. The updater verifies its signature
against the installed key, preserves enrollment/credentials/profiles/module settings
and refreshes runtime/service registration. It enables signed profile synchronization;
password-backed task provisioning stays local. Do not overwrite enrolled agent.json.

For framework verification/repair, with the service stopped:
  .\runtime\scripts\install-windows-execution-prerequisites.ps1
Initial setup already runs this helper automatically. It preserves enrollment and
changes only verified framework path/hash. Keep the service stopped after failure.

DIAGNOSTICS AND RECOVERY
Use Windows Logs -> Application for structured worker.error and job.preparation_error
stages/types/codes. Use Task Scheduler Operational events for task launch/logon errors.
Event completion alone does not establish Atomic success; inspect the run evidence.

The fixed wrapper supports Windows PowerShell 5.1 platform variables and preserves
identity/module-hash checks. A cached test YAML rejected for empty input_arguments
needs re-approval in Test Catalog to create corrected files, not re-enrollment.

Unknown results, live processes or failed workspace removal hold the actor. Preserve
journals/evidence, independently verify process termination and host effects, and
record administrator reconciliation before archiving the exact local journal. No
execution is automatically replayed. Password-backed tasks are noninteractive and
cannot establish access to the signed-in user's desktop.

Package hashes detect corruption; this ZIP/scripts are not Authenticode-signed.
Validate native service/token/containment behavior on the intended Windows host.
