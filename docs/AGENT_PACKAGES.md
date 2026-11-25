# Windows agent downloads

Administrators generate actor-specific ZIPs from **Actors → hostname → Generate agent**. The API builds them in memory from an explicit source allowlist. Generation creates no local accounts, approves no tests and starts no agent.

## Package choices

Select the canonical reachable HTTPS API URL and intended delivery mode. **On demand** is the default and requires no host catalog pin. **Pinned checkout** additionally selects an imported exact commit and requires protected machine-wide Git for Windows.

Include enrollment for initial installation. Its single-use token is bound to actor UUID, hostname and platform and defaults to 60 minutes from generation. **Settings → Agent enrollment** persists a 5–1,440-minute lifetime for future issuance. Generate a fresh package if its token expires. Regeneration invalidates earlier unused tokens for that actor.

Use a configuration-only package for runtime maintenance on an enrolled actor. It contains no installation token and does not replace installed credentials. Replacement enrollment requires disabling the actor and resolving active/uncertain work.

## Package contents

- `Install-Agent.ps1` and `Update-Agent.py`: initial installer and signed runtime updater.
- `agent.json`, `bootstrap.json`, `job-signing-public.pem`: actor metadata, enrollment/trust settings and verification key.
- `runtime/`: allowlisted agent/support source, fixed PowerShell wrappers/helpers and Python dependency requirements.
- `manifest.json`: package metadata and hashes; runtime update signatures are verified against the installed signing key.
- `README.txt`: setup and maintenance instructions.
- Public CA certificate when explicitly configured by the control plane; actor-bound catalog metadata when checkout delivery selects a commit.

Server environment files, private keys, databases, human credentials and other actors' secrets are excluded. Compare the ZIP's SHA-256 with the trusted UI before extraction. The ZIP/scripts are not Authenticode-signed; follow the organization's script policy.

## HTTPS trust

Bundled Keycloak deployments include their public CA. The download dialog shows subject, validity and SHA-256 fingerprint. The elevated installer validates it and imports that single root into `LocalMachine\Root` before verified HTTPS preflight/enrollment. Repeated installation reuses it. Trust remains after an installation failure or agent uninstall.

`-SkipCATrust` uses separately managed trust but still requires successful verified HTTPS. `-WhatIf` changes nothing. Without a bundled root, provision trusted PKI first. Custom deployments can configure `ATOMIC_AGENT_PUBLIC_CA_FILE` to one valid public self-signed root; private keys, combined trust bundles and unrelated URL origins are refused. Only public trust material is packaged.

## Install on Windows

Use Administrator **Windows PowerShell 5.1** and a protected all-users Python 3.12+ installation accessible to LocalSystem and execution accounts. Per-user/AppData/WindowsApps interpreters are unsuitable. Python and its dependencies must remain protected from profile writes.

From the extracted `AtomicControlAgent` directory:

```powershell
.\Install-Agent.ps1 -PythonPath 'C:\Program Files\Python313\python.exe' -StartService
```

Replace the Python path. The installer validates host/token/package, certificate and HTTPS, installs runtime dependencies, installs/verifies pinned Invoke-AtomicRedTeam and its all-users YAML dependency, and records the module path/hash in protected configuration. Prerequisite setup completes before enrollment. It then stores the machine credential with DPAPI and registers `AtomicControlAgent` stopped; `-StartService` starts it after successful setup.

The installer needs its Python package source, GitHub for the pinned framework ZIP and PowerShell Gallery for the pinned YAML package. Archives are checksum verified. YAML setup uses direct package download without repository-trust changes or NuGet bootstrap. No interpreter or wheel collection is bundled. On-demand installation downloads no Atomic catalog or test payloads. Test-specific external prerequisites remain locally provisioned.

A matching installed framework is verified/reused; differing files are preserved and setup stops before enrollment. The installer refuses a running service or unresolved local journal. If a later step fails after enrollment, inspect stored host identity and server state before replacing anything. Do not remove journals to force another installation.

## Provision execution identities

Register existing local account SIDs through **Actors → hostname → Execution profiles**. Metadata synchronizes automatically. Provision only the needed standard-user/elevated fixed tasks on the host with the bundled `runtime/scripts/provision-profiles.ps1`, using the service's exact all-users Python.

Passwords are entered only in the local Windows prompt. Accounts need **Log on as a batch job**; applicable deny policy overrides an allow. Standard profiles cannot belong to Administrators. Elevated profiles require the exact elevated administrator token. Choose **Retry validation** after provisioning and inspect actual evidence. See [execution setup](EXECUTION_SETUP.md#windows-automatic-profiles) and [identity requirements](EXECUTION_IDENTITIES.md).

## Configuration-only downloads

For an enrolled actor, use a fresh configuration-only ZIP, verify/extract it and follow [runtime updates](EXECUTION_SETUP.md#windows-automatic-profiles). The service must be stopped and current work resolved. The signed updater preserves actor ID, encrypted credential, profiles, module settings and signing key, refreshes runtime/service registration and enables profile synchronization. It leaves the service stopped until explicitly started.

The framework helper can install/verify the pinned execution framework with the service stopped; see [execution prerequisites](WINDOWS_EXECUTION_PREREQUISITES.md). Updating the runtime does not require deleting the actor or re-enrollment.

## Pinned checkout delivery

When selected, the package includes `catalog.json` bound to the actor, hostname, imported revision and definition hashes. Before enrollment, the installer fetches that exact official commit, disables hooks/credential helpers, verifies clean content and protects the checkout. Dirty/different existing content is retained and refused. Catalog setup executes no Atomic test or prerequisite command and grants no catalog approval.

Heartbeats report a revision only while the clean checkout and recorded verification receipt match. Custom definitions need matching protected content and cannot be fetched from an arbitrary repository. On-demand actors do not use this host-catalog workflow.

## Actor deletion and Linux packages

Delete an actor through its confirmation dialog to release its hostname and invalidate enrollment state. Uninstall its host software separately after cleanup. A replacement registration receives a new UUID, enrollment and profile IDs and inherits no tasks/jobs. See [actor deletion](SYSTEM_GUIDE.md#delete-an-actor).

Linux packages use the same generation endpoint and token lifetime, with a systemd installer and separate runner. See [Linux installation](LINUX_AGENT.md).
