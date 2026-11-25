# Linux agent

The Linux agent polls the control plane over outbound verified HTTPS and runs reviewed bash/sh tests through a fixed systemd runner. On-demand delivery supplies one test and its declared files per attempt and removes them after execution. No full host catalog or Git is required for this mode.

## Requirements

Use Linux with a running systemd 245+ system manager, unified cgroup v2, Python 3.12+ with venv/pip, `/bin/bash` and `/bin/sh`. The broker runs as root to dispatch registered non-root or root identities. Execution accounts must exist locally. Per-test external software is provisioned separately. Windows executors, Linux PowerShell/manual executors, arbitrary input overrides and automatic prerequisite installation are unsupported.

## Register and download

1. Run `hostname` and `id atomic-user` on the intended host. Obtain the actual account and numeric UID.
2. In **Actors → Add actor**, choose **Linux (systemd)** and register the exact hostname.
3. Add a standard-user profile with the actual local account/UID. Add root/UID 0 only when elevated tests are intended.
4. Generate the agent ZIP with the reachable hostname-based HTTPS API URL, **On demand**, and enrollment enabled for initial installation.
5. Compare the downloaded ZIP SHA-256 with the UI and transfer/extract it privately on the named host.

The initial installation token is single-use and defaults to 60 minutes from generation. Administrator **Settings → Agent enrollment** can set 5–1,440 minutes for future packages. Replacement enrollment requires disabling the actor and resolving active/uncertain work.

## Trust HTTPS and install

Copy only the control plane's public CA to the actor and compare its SHA-256 certificate fingerprint with the server. For Debian/Ubuntu-based hosts:

```sh
openssl x509 -in ./atomic-control-ca.crt -noout -fingerprint -sha256
sudo install -m 0644 ./atomic-control-ca.crt /usr/local/share/ca-certificates/atomic-control.crt
sudo update-ca-certificates
curl --fail --show-error https://control.example.test:19443/health
```

Use the deployment's actual hostname/port. Expect `mode: real`. Python transport uses system CA trust; `SSL_CERT_FILE`/`SSL_CERT_DIR` can select a protected custom trust store. Keep certificate verification enabled and transfer no private key.

From the extracted `AtomicControlAgent` directory, using a Python 3.12+ executable:

```sh
sudo /usr/bin/python3 -I install.py --check-only
sudo /usr/bin/python3 -I install.py
sudo systemctl enable --now atomic-control-agent
sudo systemctl status atomic-control-agent --no-pager -l
```

The installer performs verified HTTPS preflight, validates package hashes/host/token, creates protected paths and an isolated `/opt/atomic-control/venv`, installs dependencies, enrolls and registers a **disabled, stopped** service. The explicit enable/start command begins heartbeats. Package generation bundles source, not an interpreter or wheels; an approved pip/wheel source can supply dependencies. Installation downloads no Atomic tests or payloads.

The extracted bootstrap token is cleared after successful enrollment. Do not copy a package's configuration over an enrolled agent. Credentials and profile metadata live in protected host state; runtime updates preserve them.

## First heartbeat after enrollment

Actor details can show **Enrolled — waiting for first heartbeat** until the service starts. Inspect failures with:

```sh
sudo journalctl -u atomic-control-agent -b -n 60 --no-pager
```

For `sudo: unable to resolve host`, use `sudoedit /etc/hosts` and add the actual hostname to the `127.0.1.1` entry while preserving localhost entries. For example: `127.0.1.1 linux-host-01`.

The installer creates protected runtime/catalog paths. An empty catalog directory is not a verified checkout, and on-demand execution does not require a catalog pin. A **Pinned checkout** actor additionally needs **Actors → hostname → Configure catalog**; see [catalog setup](EXECUTION_SETUP.md#install-and-pin-the-linux-catalog).

## Profiles and runtime updates

Registered profile changes synchronize automatically while idle through actor-bound signed generations. The agent validates existing accounts with identity-only probes and reports profile health. Correct host lookup/UID/systemd issues and choose **Retry validation** when needed. Registration does not create accounts or grant sudo. Do not edit `validated` manually.

Use a configuration-only ZIP and signed updater to update an enrolled actor with its service stopped. Keep its actor ID, credential and signing key. Follow [Linux runtime updates](EXECUTION_SETUP.md#update-the-linux-runtime); do not merge downloaded profile JSON into installed credentials/configuration manually.

A manual identity probe is available for local maintenance while the service is stopped:

```sh
sudo /opt/atomic-control/venv/bin/python -I -m apps.agent.linux.service --validate-profiles
```

A process lock prevents simultaneous agents/probes. Restart the service after completing maintenance.

## Installation recovery

If installation directories exist but enrollment did not complete, download a fresh enrollment ZIP for the same actor, verify/extract it privately, correct HTTPS/host setup and run:

```sh
sudo /usr/bin/python3 -I install.py --resume-enrollment --check-only
sudo /usr/bin/python3 -I install.py --resume-enrollment
```

Resume accepts only an empty, unenrolled installation. It refuses existing credentials/configuration, active or unknown work, an installed/enabled service and unprotected paths. Keep refused state intact and investigate rather than deleting it to bypass the guard. The service remains stopped until explicitly enabled.

## Identity and execution

Each attempt starts a fixed runner in a transient systemd service under the approved UID/primary GID. The runner verifies grant/platform/snapshot/profile and exact test content before launching a shell. It uses reviewed defaults and `PathToAtomicsFolder`; unresolved inputs fail before invocation. `check` runs reviewed prerequisite checks; prerequisite installation commands never run. Cleanup is separately authorized.

Identity evidence includes real/effective/saved/filesystem UID/GID, supplementary groups, capability masks, NoNewPrivs, account and process ID. Standard profiles require non-root identity, no root group or capabilities, and NoNewPrivileges. Elevated profiles require UID/GID 0 and catalog approval for that profile. API validation independently checks Linux evidence.

Credentials use root-only directories/files and atomic durable rotation. Filesystem protection is not encryption. Root-approved tests have host authority; systemd is not a security boundary against a hostile root process.

## Interrupted jobs and maintenance

The broker bounds output, renews leases and stops the complete attempt cgroup on cancellation, lost connectivity, shutdown or timeout. It verifies descendant cgroups have no processes before confirming termination/removal. On-demand attempt files are removed after termination, while durable evidence/journals support reporting recovery.

An uncertain outcome preserves `/var/lib/atomic-control/jobs/active.json` and blocks new execution; the server retains the actor lease and marks expired work inconclusive. Recovery never replays a test. Stop the recorded `atomic-control-job-<attempt_id>.service`, independently verify its cgroup and host effects, and record administrator reconciliation before archiving the exact journal. See [workspace recovery](ON_DEMAND_TEST_DELIVERY.md#recovery).

Complete distribution-specific service, identity, containment and recovery acceptance from [validation](VALIDATION.md). Isolated systemd tests do not establish native host behavior.
