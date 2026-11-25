# Atomic Control operations reference

Use the [installation guide](INSTALLATION_GUIDE.md) for a new control plane and the [user guide](SYSTEM_GUIDE.md) for dashboard tasks. This reference covers routine service operation, automatic startup, backups and maintenance of the bundled Keycloak deployment.

Run commands from the repository root. The application runtime reads the existing protected `artifacts/keycloak/application.env`. Every `apps.local_identity.setup` action regenerates that file from standard settings, including `status`, `stop` and `provision`; back up and reapply custom overrides before using those commands. Routine Docker commands below leave it unchanged.

## Start and stop

### Start and stop manually

For an unchanged installation with the identity containers already running, start the application with:

```sh
.venv/bin/python -m apps.local_identity.runtime
```

Ctrl+C in that terminal stops the API/dashboard and MCP children. It does not stop Keycloak/PostgreSQL or uninstall execution agents. If a service manager owns the runtime, use its stop/start commands rather than starting another copy.

For routine identity status/log/stop/start operations without regenerating `application.env`:

```sh
# These commands use the existing Compose environment and do not recreate services.
docker compose --env-file artifacts/keycloak/compose.env \
  -f deploy/keycloak/compose.yaml ps

docker compose --env-file artifacts/keycloak/compose.env \
  -f deploy/keycloak/compose.yaml logs --tail=100 keycloak postgres

docker compose --env-file artifacts/keycloak/compose.env \
  -f deploy/keycloak/compose.yaml stop keycloak postgres

docker compose --env-file artifacts/keycloak/compose.env \
  -f deploy/keycloak/compose.yaml start postgres keycloak
```

The base file resolves the same named project/services in either network profile for these non-recreating commands. Use `setup up` when initially provisioning or applying network/TLS changes; it includes the LAN override when required. Do not use `docker compose down -v` for routine shutdown: that removes persistent identity data.

The application runtime inherits standard output/error unless redirected by your service manager. A private foreground log command is:

```sh
umask 077
.venv/bin/python -m apps.local_identity.runtime \
  >> artifacts/keycloak/runtime.log 2>&1
```

This still runs in the foreground. Protect and rotate logs; do not enable request logging that records OIDC callback query strings or tokens.

### Linux: service-manager template

After verifying the [Linux management-host installation](INSTALLATION_GUIDE.md#linux-alternative-ubuntu-server-2404-lts), you can run the supervisor under systemd. This example assumes the checkout and private runtime already belong to an existing `atomic-control` account at `/opt/atomic-control`. If you installed using another login account, replace `User` and `Group` below with the output of `id -un` and `id -gn` from that account. Keep the service under the same owner that generated the private runtime, including its browser-session key. Substitute your real absolute path if different; do not relocate an existing installation without updating its generated paths.

Create the unit with:

```sh
sudoedit /etc/systemd/system/atomic-control-control-plane.service
```

Save the following after substituting the account, group and paths:

```ini
[Unit]
Description=Atomic Control HTTPS control plane and MCP
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=simple
User=atomic-control
Group=atomic-control
WorkingDirectory=/opt/atomic-control
ExecStart=/opt/atomic-control/.venv/bin/python -m apps.local_identity.runtime
Restart=always
RestartSec=5
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable Docker Engine with `sudo systemctl enable --now docker`. The provisioned Keycloak/PostgreSQL containers use `restart: unless-stopped`; explicitly stopped containers must first be started with the routine Compose commands above. This unit manages the host API/MCP only; it does not provision Keycloak, run Docker setup or install an execution agent. Then, after stopping the manually started runtime:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now atomic-control-control-plane
sudo systemctl status atomic-control-control-plane --no-pager -l
sudo journalctl -u atomic-control-control-plane -b -n 100 --no-pager
```

Use `sudo systemctl stop atomic-control-control-plane` before upgrades. The actor's separate service is named `atomic-control-agent`; do not confuse the two.

### macOS: login service template

For startup when the installation user logs in, configure Docker Desktop to start at login and create `~/Library/LaunchAgents/com.atomiccontrol.runtime.plist`. Replace every example absolute path below with your checkout. Do not load it while the manual runtime is running.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.atomiccontrol.runtime</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOUR_USER/Projects/Atomic-Control/.venv/bin/python</string>
    <string>-m</string><string>apps.local_identity.runtime</string>
  </array>
  <key>WorkingDirectory</key><string>/Users/YOUR_USER/Projects/Atomic-Control</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>/Users/YOUR_USER/Projects/Atomic-Control/artifacts/keycloak/runtime.log</string>
  <key>StandardErrorPath</key><string>/Users/YOUR_USER/Projects/Atomic-Control/artifacts/keycloak/runtime.log</string>
</dict>
</plist>
```

The checkout, log directory and generated private files must already exist. Restrict the plist to its owner, validate it and register it in that user's GUI session:

```sh
chmod 600 "$HOME/Library/LaunchAgents/com.atomiccontrol.runtime.plist"
plutil -lint "$HOME/Library/LaunchAgents/com.atomiccontrol.runtime.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.atomiccontrol.runtime.plist"
launchctl print "gui/$(id -u)/com.atomiccontrol.runtime"
```

Stop/unregister it before maintenance:

```sh
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.atomiccontrol.runtime.plist"
```

This is a per-user login service, not an unattended pre-login server. Docker must still be running and the identity containers available before users can sign in. These service-manager examples are templates to validate on the target host, not automatically installed components.

## Backups, upgrades and recovery

### Back up a consistent deployment

Finish active work, stop the API/MCP runtime and avoid new administration changes during the backup. Keep an encrypted/off-host backup of:

- The current repository revision and dependency lockfiles.
- The complete private `artifacts/keycloak` directory, including signing keys, CA/TLS material, browser session key, environments, policy and application state.
- Keycloak's PostgreSQL data, using a PostgreSQL logical backup or a documented consistent volume backup.

The application database and identity database are separate. The browser-session encryption key must accompany the SQLite backup; preserving SQLite alone cannot restore encrypted sessions. Do not rotate or discard the job-signing key during a normal restore, because agents pin its public counterpart.

A private local backup example, with the application stopped:

```sh
umask 077
ATOMIC_BACKUP_DIR="artifacts/backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ATOMIC_BACKUP_DIR"

# SQLite's backup API captures the database consistently, including WAL-backed state.
.venv/bin/python - "$ATOMIC_BACKUP_DIR/application.db" <<'PY'
import sqlite3
import sys
from dotenv import dotenv_values
values = dotenv_values('artifacts/keycloak/application.env', interpolate=False)
url = values['ATOMIC_DATABASE_URL']
if not url.startswith('sqlite:///'):
    raise SystemExit('This backup example is for the bundled SQLite profile')
with sqlite3.connect(url[len('sqlite:///'):]) as source:
    with sqlite3.connect(sys.argv[1]) as target:
        source.backup(target)
PY

docker compose --env-file artifacts/keycloak/compose.env \
  -f deploy/keycloak/compose.yaml exec -T postgres \
  pg_dump -U keycloak -d keycloak --format=custom \
  > "$ATOMIC_BACKUP_DIR/keycloak.dump"

tar -czf "$ATOMIC_BACKUP_DIR/private-runtime.tar.gz" artifacts/keycloak
git rev-parse HEAD > "$ATOMIC_BACKUP_DIR/source-revision.txt"
```

Keep PostgreSQL running for `pg_dump`. Check each command succeeds before moving the backup to protected storage; the archive contains secrets. Do not commit these backup files. Merely copying a live `.db` without its WAL state is not a reliable backup.

For restore, stop the application and identity services, restore a compatible application database/private runtime and PostgreSQL backup using the matching PostgreSQL tools, and preserve ownership/permissions. If restoring the application database from `application.db`, remove or archive stale SQLite WAL/SHM files only after all database users are stopped. Validate the restored revision/schema and identity ownership before reopening access. Retain the pre-restore state until sign-in, actor authentication and history checks pass. Restoring a backup that predates current machine credentials may require deliberate credential recovery; it is not a reason to silently replay jobs.

### Upgrade the application

1. Finish active jobs and required cleanup, inspect any inconclusive work, and stop the runtime/service manager.
2. Create and verify a backup and record the current source revision.
3. Update to the reviewed repository revision without discarding local changes or private runtime files.
4. Run `.venv/bin/python -m pip install -r requirements.txt` and `pnpm --dir apps/frontend install --frozen-lockfile`.
5. Run `pnpm --dir apps/frontend build`.
6. Start `apps.local_identity.runtime` through your existing terminal/service manager. It applies migrations with the generated private environment.
7. Verify health/readiness, SSO, roles, actors and history. Upgrade host agents only when a new capability requires it, using their configuration-preserving update workflow.

Do not run a second migration/start command against a live deployment. A rollback after a schema change requires its own migration/backup plan; replacing Python files alone may not reverse the database safely. Normal application upgrades do not require new actor enrollment or regenerated signing keys. Preserve persisted user-access revocations: the schema deliberately refuses to discard them after account changes. Restore application and identity-provider state together when rollback requires a backup.

### Change the LAN address

Keep the same DNS names so browsers and agents can retain their service URLs. Finish active work, stop the runtime and identity containers, and back up the private runtime and custom environment settings. Confirm the new private address is assigned to the management host, then run the following with your new address/subnet and the **existing public and identity hostnames**:

```sh
.venv/bin/python -m apps.local_identity.setup network \
  --address 10.20.30.10 --subnet 10.20.30.0/24 \
  --public-hostname control.example.test \
  --identity-hostname control.example.test
.venv/bin/python -m apps.local_identity.setup up
```

Update DNS and firewall rules for the new address. Reapply intentional `application.env` overrides after the final setup call. Preserve the CA signing key and distribute the current public CA certificate where trust needs updating. Restart the runtime and verify browser sign-in and an agent heartbeat. This changes no installed agent configuration automatically.

Pass both hostname flags on subsequent network changes; omitting them selects IP-based URLs. If migrating from IP-based URLs or changing an issuer, follow [the hostname migration procedure](KEYCLOAK.md#use-a-dns-hostname-for-native-codex-oauth), including agent URL/trust updates where required.

To return to host-only access, use `setup network --loopback`, then `setup up`, refresh trust and restart. Remote actors will no longer reach the server through that profile.

### Renew local certificates

Service certificates last 90 days and the generated CA lasts 365 days; renewal is manual. Before expiry, stop the runtime and identity containers and back up the private runtime. Preserve the CA key, all service private keys, signing key, encryption key and credentials. Archive the three public service certificates `tls/control.pem`, `tls/keycloak.pem` and `tls/mcp.pem` outside `tls/`, then run `setup prepare` and `setup up` to regenerate/reinstall certificate material. Reapply custom environment values, replace trust entries where the generated CA certificate changed, and restart/verify the runtime.

Do not delete the whole private directory to renew certificates. See [certificate trust](KEYCLOAK.md#https-trust) for the local certificate implementation and trust update details.
