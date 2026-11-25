# Configure execution through the dashboard

Sign in as an administrator on the HTTPS deployment. The default workflow is **enroll host → register/provision identities → approve intended tests → run or queue**. On-demand agents need no host catalog checkout. Installation, profile synchronization and identity probes do not run Atomic tests.

## Register the execution account

Create the intended account locally before registering its identity. In **Actors → hostname → Add execution profile**, select Standard user or the elevated profile, enter its display/account names and actual identity, acknowledge host verification, then choose **Register execution profile**.

| Platform/profile      | Identity to register | Host requirement                                         |
| --------------------- | -------------------- | -------------------------------------------------------- |
| Linux standard user   | Actual `uid:N`       | Non-root account, no root group/capabilities             |
| Linux elevated        | `uid:0`              | Root account with UID/GID 0                              |
| Windows standard user | Actual local SID     | Non-administrator account and medium-integrity token     |
| Windows elevated      | Actual local SID     | Administrator account with high-integrity elevated token |

On Linux, obtain the values with `hostname` and `id atomic-user`; use the actual UID, not an assumed value. On Windows, use `Get-LocalUser` to obtain the local SID. The account's name does not establish its privilege.

Profiles have immutable IDs/account bindings. Registration creates no local account, password, permission grant or healthy result. Profile synchronization and host probes establish health.

## Apply and validate Linux profiles automatically

The idle agent fetches signed profile generations, verifies actor/platform/hash, updates protected metadata and runs identity-only probes. Its API URL, credential and signing key remain intact. Additions/removals require no re-enrollment.

Actor details show **Waiting for validation**, **Validating** and **Ready**, or **Needs attention** with a bounded failure reason. Offline agents show **Waiting for agent**; an actor without an enabled profile needs a profile. Correct the host issue and choose **Retry validation** when needed. Healthy profiles can remain usable when another profile fails validation; failed configuration application blocks new claims. Active leases and uncertain local journals defer synchronization.

### Update the Linux runtime

Finish or reconcile current work, download a configuration-only ZIP for the same actor, verify its checksum and extract it privately. For an on-demand package, run from `AtomicControlAgent`:

```sh
(
  set -e
  sudo systemctl stop atomic-control-agent
  sudo /opt/atomic-control/venv/bin/python -I Update-Agent.py --enable-profile-sync --enable-on-demand --check-only
  sudo /opt/atomic-control/venv/bin/python -I Update-Agent.py --enable-profile-sync --enable-on-demand
  sudo systemctl start atomic-control-agent
)
```

The signed updater checks the installed signing key and identity and refuses active/unreconciled work. It preserves enrollment. On failure, leave the service stopped and inspect the error. Package update signatures expire after seven days; download a fresh package when needed. For checkout delivery, use `--enable-catalog-sync` in place of `--enable-on-demand`.

## Install and pin the Linux catalog

This section applies to actors configured for **Pinned checkout** delivery. On-demand actors receive their exact files per attempt.

Open **Actors → hostname → Configure catalog**, select an imported commit, review its full SHA and definition count, acknowledge the named target and choose **Install pinned catalog**. The idle agent uses Git to fetch the exact official commit, verifies clean/root-owned files and imported definition hashes, preserves the prior checkout and reports the verified pin. Installation executes no test or prerequisite commands.

Git, verified HTTPS access to GitHub and at least 1 GB free beside the catalog are required. Active/uncertain work defers installation. Errors expose an explicit retry. Heartbeats withdraw the reported pin if the checkout drifts. Preserve installation journals when recovery cannot establish the prior state. Catalog installation does not approve tests.

### Windows automatic profiles

Windows agents fetch signed profile additions/removals while idle and retain their enrolled identity. Existing local accounts and password-backed scheduled tasks must be provisioned on the host.

After a registered profile appears in `C:\ProgramData\AtomicControl\agent.json`, run the package's helper from Administrator PowerShell, using the service's actual protected all-users Python:

```powershell
.\runtime\scripts\provision-profiles.ps1 `
  -ConfigFile 'C:\ProgramData\AtomicControl\agent.json' `
  -PythonPath 'C:\Program Files\Python313\python.exe' `
  -InstallRoot 'C:\Program Files\AtomicControl\runtime'
```

Enter account passwords only in the local Windows prompt. Grant the intended accounts **Log on as a batch job** through local/domain policy; an applicable deny overrides the grant. The helper does not create accounts or grant those rights. Then choose **Retry validation**. The agent verifies task definitions, permissions and actual SID/token before reporting health. Do not manually set `validated=true`.

For a runtime update, finish/reconcile work, generate a fresh configuration-only ZIP for the same actor, verify/extract it and run:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $python = 'C:\Program Files\Python313\python.exe'
    Stop-Service AtomicControlAgent
    & $python -I .\Update-Agent.py --enable-on-demand --check-only
    if ($LASTEXITCODE -ne 0) { throw 'Update preflight failed; leave the service stopped.' }
    & $python -I .\Update-Agent.py --enable-on-demand
    if ($LASTEXITCODE -ne 0) { throw 'Runtime update failed; leave the service stopped.' }
    Start-Service AtomicControlAgent
}
```

Use the package's intended delivery mode: omit `--enable-on-demand` for checkout mode. Updates preserve actor identity, credentials, profiles and signing key and enable automatic profile synchronization. Task passwords stay local. See [Windows identity requirements](EXECUTION_IDENTITIES.md) and [Python/task-path repair](WINDOWS_PROFILE_REPAIR.md).

## Delete an execution profile

Choose **Actors → hostname → Execution profiles → Delete profile**, review the account and confirm. Finish required cleanup first. Deletion cancels waiting requests for that profile and retains run/audit history; active/uncertain work and applying configuration block deletion. Local accounts/files remain. A replacement profile receives a new UUID.

Agents receive removals while idle. Linux removes the metadata; Windows also removes verified fixed execution/probe tasks. Server authorization for the deleted profile ends immediately.

## Delete an actor

Use **Actors → hostname → Delete actor…**, optionally enter a reason and confirm the exact hostname. Finish cleanup and reconcile uncertain work first. Active leases and applying configuration/catalog operations block deletion. Registration, profiles and credentials are deleted, waiting work is cancelled and the hostname can be reused with a new actor UUID/enrollment. Execution/audit evidence remains. Uninstall host software separately; disabling the actor is the reversible maintenance action.

## Optional per-run execution access

Default catalog mode authorizes compatible operator requests under exact catalog approval. When `ATOMIC_APPROVAL_MODE=per_run`, a human administrator manages exact subject/actor/profile/test/risk/action grants through `GET /api/v1/execution-access`, `POST /execution-access/preview` and `POST /execution-access/apply` under the same API prefix. Previews expire after five minutes and reject stale policy/target versions. These endpoints do not approve or run tests. See [API authorization](API.md#authorization).

## Understand actor eligibility

Select a test in **Execute Test** and expand **Actor eligibility and setup**. Only matching-platform actors appear. Matching but offline/unhealthy hosts remain visible with readiness reasons. Check host enablement/heartbeat, executor/platform, allowed healthy identity, required external tools and approved file availability. Checkout actors additionally need their exact verified catalog revision.

An approved inline test requires no separate supporting-file approval; Run/Queue prepares its bundle automatically. Catalog mode queues an explicit request under the catalog review. Per-run mode waits for a separate approval. Technical compatibility alone grants no authorization.
