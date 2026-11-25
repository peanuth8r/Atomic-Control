LINUX AGENT — SOURCE INSTALLER

Requires Python 3.12+, systemd 245+, unified cgroup v2 and bash/sh.
This ZIP is bound to the actor ID, hostname and server printed above.
Verify its SHA-256 against the trusted HTTPS UI and extract privately.
Install before the enrollment expiry shown above/in bootstrap.json; the default
is 60 minutes and administrators can tune future issuance in Settings.
Configuration-only packages update an enrolled host and cannot enroll one.

INSTALL AND START
1. Trust the control plane's public CA in the host system trust store. Compare
   its certificate fingerprint with the server. On Debian/Ubuntu-based hosts:
     sudo install -m 0644 atomic-control-ca.crt /usr/local/share/ca-certificates/atomic-control.crt
     sudo update-ca-certificates
     curl --fail https://YOUR_CONTROL_HOSTNAME:19443/health
   Transfer no private key. Keep verified TLS enabled. SSL_CERT_FILE/SSL_CERT_DIR
   can select a protected custom trust store.
2. From this extracted directory, using a Python 3.12+ executable:
     sudo /usr/bin/python3 -I install.py --check-only
     sudo /usr/bin/python3 -I install.py
3. The installer leaves a stopped/disabled service. Start it explicitly:
     sudo systemctl enable --now atomic-control-agent
     sudo systemctl status atomic-control-agent --no-pager -l
   Inspect startup failures:
     sudo journalctl -u atomic-control-agent -b -n 60 --no-pager

Setup validates the package/host/HTTPS, creates protected paths and an isolated
/opt/atomic-control/venv, installs dependencies and enrolls. Approved pip/wheel
sources may supply dependencies. It downloads no Atomic tests, creates no local
accounts and grants no sudo rights.

If sudo cannot resolve the host, use sudoedit /etc/hosts and include the actual
hostname in the 127.0.1.1 entry while preserving localhost entries. Example:
  127.0.1.1 linux-host-01

PROFILES AND TESTS
Register actual accounts/UIDs under Actors -> hostname -> Add execution profile.
The existing local account must match exactly. standard-user requires non-root
identity; local-admin means root UID/GID 0 on Linux. Signed metadata additions
and removals synchronize automatically while idle and run identity-only probes.
Use Retry validation after correcting host issues; do not set validated by hand.

On-demand delivery downloads only the current approved test and declared files
and removes them afterward. Run/Queue prepares the approved bundle automatically.
No full catalog or Git is required. Provision external test software separately.
Prerequisite checks execute reviewed check commands; installation commands never run.

Selectable pinned-checkout mode additionally requires Git and a protected clean
checkout matching the reviewed revision. Actors -> hostname -> Configure catalog
installs/verifies an imported exact official commit while idle. A requested commit
or empty directory is not a verified checkout. This step is unnecessary on demand.

RUNTIME UPDATE
Finish/reconcile work, download a fresh configuration-only ZIP for this same actor,
verify/extract it and stop the service. For an on-demand package:
  sudo systemctl stop atomic-control-agent
  sudo /opt/atomic-control/venv/bin/python -I Update-Agent.py --enable-profile-sync --enable-on-demand --check-only
  sudo /opt/atomic-control/venv/bin/python -I Update-Agent.py --enable-profile-sync --enable-on-demand
  sudo systemctl start atomic-control-agent
Stop after an error and leave the service stopped until understood. The signed
updater preserves actor identity, credentials and signing key and refuses uncertain
work. Do not copy the ZIP's agent.json over the enrolled configuration. For checkout
mode, use --enable-catalog-sync instead of --enable-on-demand.

FAILED FIRST ENROLLMENT
Correct CA/DNS/connectivity and generate a fresh enrollment ZIP for the same actor
if expired. An empty, unenrolled installation can resume from that new package:
  sudo /usr/bin/python3 -I install.py --resume-enrollment --check-only
  sudo /usr/bin/python3 -I install.py --resume-enrollment
Resume refuses installed credentials/configuration, unknown work or an enabled unit.
Preserve refused state and investigate; never delete it to bypass the guard.

CREDENTIALS AND RECOVERY
Credentials are protected by root-only files/directories, not disk encryption.
Standard runners have no capabilities and use NoNewPrivileges. Root tests have host
authority; cgroups are lifecycle controls, not a sandbox against a hostile root test.

The durable /var/lib/atomic-control/jobs/active.json journal prevents replay after
interruption. Verify the recorded attempt's systemd cgroup/processes stopped,
inspect host effects and files, and record administrator reconciliation before
archiving that journal. Automatic workspace removal does not perform test cleanup.
Cleanup is a separate authorized run. Unknown execution is never automatically retried.
