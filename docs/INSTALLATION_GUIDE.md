# Atomic Control installation guide

Install the control plane, sign in, then follow the [user guide](SYSTEM_GUIDE.md) to add hosts and run approved tests. This guide uses the bundled Keycloak deployment. Choose **macOS with Docker Desktop** or **Linux with Docker Engine**; the Linux commands below target a fresh **Ubuntu Server 24.04 LTS** host with systemd. Other distributions need equivalent packages and Docker installation steps.

Keycloak and its PostgreSQL database run in Docker. The API, built dashboard and MCP service run on the management host; the application database is SQLite. Execution agents run on separate Windows or Linux hosts. Installation does not run Atomic tests.

## 1. Prepare the management host

Use a regular installation account with sudo access. Keep the checkout, virtual environment and generated private files owned by that account. Only operating-system package installation, certificate trust, firewall and service-manager commands below use sudo.

Install these tools before continuing:

| Tool    | Requirement                                  |
| ------- | -------------------------------------------- |
| Python  | 3.12+, with venv and pip                     |
| Node.js | 22.12+                                       |
| pnpm    | 10.24.0, matching repository CI              |
| Docker  | Running Engine/Desktop with `docker compose` |
| Other   | Git, curl and OpenSSL                        |

Allow space for dependencies, container images, catalog content and backups. For a small installation, start with about 4 CPU cores, 8 GB RAM and 20 GB free disk; this is a planning estimate. Keep server and actor clocks synchronized.

### macOS alternative

Install Python 3.12+, [Node.js 24 LTS](https://nodejs.org/en/download), Git and Docker Desktop. Start Docker Desktop before continuing. If its CLI is missing from PATH, add `$HOME/.docker/bin` to PATH. Install the repository's pnpm version as your installation account:

```sh
npm install --global pnpm@10.24.0
```

### Linux alternative: Ubuntu Server 24.04 LTS

Connect through SSH or a local terminal. Install Python and build tools:

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip python3-dev \
  build-essential libssl-dev libffi-dev pkg-config ca-certificates curl git openssl
```

Install Node.js 24 LTS through [nvm's documented installer](https://github.com/nvm-sh/nvm#install--update-script). This installs Node/npm under the installation account; do not use sudo for nvm, npm or pnpm:

```sh
export NVM_DIR="$HOME/.nvm"
ATOMIC_NVM_INSTALLER="$(mktemp)"
curl --fail --show-error --location \
  https://raw.githubusercontent.com/nvm-sh/nvm/v0.41.0/install.sh \
  --output "$ATOMIC_NVM_INSTALLER"
bash "$ATOMIC_NVM_INSTALLER"
rm "$ATOMIC_NVM_INSTALLER"
. "$NVM_DIR/nvm.sh"
nvm install 24
nvm alias default 24
npm install --global pnpm@10.24.0
```

The Ubuntu archive's Node version may be older than this project's requirement. Use `nvm use 24` in a new build shell if needed. Node/pnpm build the dashboard; the running Python service does not need nvm in its PATH.

Install Docker Engine and the Compose plugin from [Docker's Ubuntu repository](https://docs.docker.com/engine/install/ubuntu/#install-using-the-apt-repository). These commands are for a fresh Ubuntu 24.04 host; if Docker is already installed, check that it works before changing its packages/repository.

```sh
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl --fail --show-error --location https://download.docker.com/linux/ubuntu/gpg \
  --output /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$(id -un)"
```

Sign out of SSH/the login session completely and sign back in before continuing. The setup helper runs Docker as the installation account, so `docker version` must work without sudo. Membership in the Docker group gives that account host-administrator privileges, as described in [Docker's post-installation guide](https://docs.docker.com/engine/install/linux-postinstall/).

### Check either management host

```sh
python3 --version
node --version
pnpm --version
docker version
docker compose version
git --version
openssl version
```

Confirm Python is 3.12+, Node is 22.12+ (the example installs 24 LTS), pnpm is 10.24.0, and `docker version` connects to the daemon. Then continue with the shared setup below.

## 2. Download and build

Choose a permanent checkout path before setup; generated configuration contains absolute paths. Use **one** of these checkout alternatives.

On macOS, from your chosen parent directory:

```sh
git clone https://github.com/peanuth8r/Atomic-Control.git
cd Atomic-Control
```

On Linux, use `/opt/atomic-control` owned by your installation account:

```sh
sudo install -d -m 0750 -o "$(id -un)" -g "$(id -gn)" /opt/atomic-control
git clone https://github.com/peanuth8r/Atomic-Control.git /opt/atomic-control
cd /opt/atomic-control
```

Build as the same account on either platform:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
pnpm --dir apps/frontend install --frozen-lockfile
pnpm --dir apps/frontend build
```

All remaining commands run from this repository root. A successful build creates `apps/frontend/dist/index.html`. For an existing installation, use the [upgrade procedure](OPERATIONS.md#upgrade-the-application) instead of starting over.

## 3. Configure the address and hostname

For remote actors, reserve a stable private IPv4 address for the management host and create an internal DNS A record pointing your chosen hostname to it. The hostname must resolve on the server, browser clients and actors. A hosts-file entry works only on the devices where you add it.

Replace all example values below with your assigned address, permitted source subnet and DNS name:

```sh
.venv/bin/python -m apps.local_identity.setup network \
  --address 10.20.30.10 \
  --subnet 10.20.30.0/24 \
  --public-hostname control.example.test \
  --identity-hostname control.example.test
```

Use hostnames for service URLs; the IP selects the server's bind/published address. Keep the same names when the server address changes. For an existing deployment, follow [hostname migration](KEYCLOAK.md#use-a-dns-hostname-for-native-codex-oauth) rather than changing a running issuer without preparation.

| Service                 | Example URL                                 | Access needed              |
| ----------------------- | ------------------------------------------- | -------------------------- |
| Dashboard and agent API | `https://control.example.test:19443`        | Browsers and actors        |
| Keycloak sign-in        | `https://control.example.test:18443`        | Browsers and control plane |
| Keycloak administration | `https://control.example.test:18443/admin/` | Identity administrators    |
| MCP                     | `https://localhost:19444/mcp`               | Local MCP clients only     |

Allow the required ports through your host/network firewall. Agents connect outbound to port 19443; this application needs no inbound remote-shell port on them. The API also filters source addresses using the configured subnet. For routed networks, ensure that filter and your firewall cover the intended actor networks. Keycloak's published port has separate firewall rules; PostgreSQL is not published.

### Linux network checks

For the example LAN configuration, confirm the reserved address is assigned and the hostname resolves on the management host:

```sh
ip -br addr
ip route
getent ahostsv4 control.example.test
```

The address must appear on a host interface, and DNS must return that same address. Remote browser clients and actors need the same DNS mapping. If UFW is already enabled, an example rule for the host API is:

```sh
sudo ufw allow from 10.20.30.0/24 to any port 19443 proto tcp
sudo ufw status
```

Adapt the source networks to your installation. Keycloak's Docker-published port 18443 needs separate Docker-aware or upstream firewall rules: published container traffic can bypass UFW's normal host rules. See [Docker's firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw). Keep port 19444 on loopback; a remote administrator can use the dashboard without exposing MCP.

For a **host-only trial**, use the following instead of the network command:

```sh
.venv/bin/python -m apps.local_identity.setup prepare
```

On a fresh host-only installation, dashboard and Keycloak URLs use `localhost`. Separate actor hosts cannot reach the server through their own `localhost`. An existing LAN selection is preserved by `prepare`.

## 4. Trust the public CA

Setup creates `artifacts/keycloak/atomic-control-ca.crt`. Copy only this public certificate to clients and compare its fingerprint with the server:

```sh
openssl x509 -in artifacts/keycloak/atomic-control-ca.crt -noout -fingerprint -sha256
```

Trust it on the management host and each connecting browser/actor. The CA covers the configured DNS names and local/LAN identities; an old certificate may lack the names needed by a changed deployment.

### macOS

On the management Mac:

```sh
security add-trusted-cert -r trustRoot -p ssl \
  -k "$HOME/Library/Keychains/login.keychain-db" \
  artifacts/keycloak/atomic-control-ca.crt
```

On another Mac, substitute the copied certificate's path. Browsers with their own trust store may require importing it there too.

### Debian or Ubuntu Linux

On the Linux management host, from the repository root:

```sh
sudo install -m 0644 artifacts/keycloak/atomic-control-ca.crt \
  /usr/local/share/ca-certificates/atomic-control.crt
sudo update-ca-certificates
```

On a separate Linux browser/actor host, first copy the public certificate and substitute its local path for `artifacts/keycloak/atomic-control-ca.crt`. Browsers with a separate certificate store may also need the public CA imported there. Current Linux agent packages use system CA trust. See [Linux trust and interrupted installation](LINUX_AGENT.md#installation-recovery) for older environments.

### Windows

For a browser user, import the copied certificate:

```powershell
certutil -user -addstore Root .\atomic-control-ca.crt
```

For a Windows actor, the fresh bundled agent ZIP includes the public CA and its installer imports it into machine trust automatically. No separate CA transfer/import is needed on that host. For manual machine trust, run from elevated PowerShell:

```powershell
certutil -addstore Root .\atomic-control-ca.crt
```

Current Windows packages use system trust for enrollment and ongoing LocalSystem service communication. The download page shows the bundled CA fingerprint; `-SkipCATrust` leaves trust management to your existing PKI. See [Windows agent setup](AGENT_PACKAGES.md).

## 5. Start the services

Start Docker, then provision the identity services:

```sh
.venv/bin/python -m apps.local_identity.setup up
```

The first start may take several minutes. It starts Keycloak/PostgreSQL, creates the owned realm and configures sign-in, application roles and the user-management client. Existing owned users and passwords are preserved.

Start the application and leave its terminal running:

```sh
.venv/bin/python -m apps.local_identity.runtime
```

The launcher reads the protected environment, applies migrations, and starts HTTPS API/dashboard and loopback MCP services. It refuses occupied ports. Ctrl+C stops those two application processes; identity containers and installed agents are separate.

**For later restarts**, use the runtime command and [routine container commands](OPERATIONS.md#start-and-stop). Every setup-helper action regenerates `application.env`, including `status`, `stop` and `provision`; back up and reapply custom settings before using it. Do not copy `.env.example` over an installed runtime.

### Linux: keep the control plane running after logout

First verify the foreground installation using section 6. Then press Ctrl+C in its runtime terminal and install the [Linux systemd unit](OPERATIONS.md#linux-service-manager-template). Set its `User` and `Group` to the installation account and group (`id -un` and `id -gn`); keep its working directory and Python path at `/opt/atomic-control` for the Linux checkout above. The same account must own and read the generated private files. Do not run the application as root.

After saving the unit as `/etc/systemd/system/atomic-control-control-plane.service`:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now atomic-control-control-plane
sudo systemctl status atomic-control-control-plane --no-pager -l
sudo journalctl -u atomic-control-control-plane -b -n 100 --no-pager
```

This service starts the API/dashboard and local MCP at boot without an SSH session. Docker Engine must also be enabled; the provisioned Keycloak/PostgreSQL containers use `restart: unless-stopped`. If containers were explicitly stopped, start them with the [routine Compose commands](OPERATIONS.md#start-and-stop-manually). The unit does not provision identity services or install the execution agent, whose service is separately named `atomic-control-agent`. Repeat the health/readiness checks after enabling the unit and after a planned reboot.

On macOS, the corresponding option is the [login-service template](OPERATIONS.md#macos-login-service-template).

## 6. Verify and sign in

In another terminal, use your configured dashboard URL:

```sh
ATOMIC_CONTROL_URL='https://control.example.test:19443'
curl --fail --show-error --cacert artifacts/keycloak/atomic-control-ca.crt \
  "$ATOMIC_CONTROL_URL/health"
curl --fail --show-error --cacert artifacts/keycloak/atomic-control-ca.crt \
  "$ATOMIC_CONTROL_URL/ready"
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  --cacert artifacts/keycloak/atomic-control-ca.crt \
  "$ATOMIC_CONTROL_URL/api/v1/me"
```

Expect `/health` and `/ready` to return HTTP 200, health to report `mode: real`, and unauthenticated `/api/v1/me` to return 401. For host-only setup, use `https://localhost:19443`.

On a headless Linux server, open the configured dashboard URL in a browser on another computer after configuring its DNS and CA trust. Open the dashboard and choose **Sign in with SSO**. Before sign-in, only the login screen is visible. Open `artifacts/keycloak/credentials.json` privately to retrieve the initial password:

| Destination                           | Username           | Password entry       |
| ------------------------------------- | ------------------ | -------------------- |
| Atomic Control dashboard              | `atomic-admin`     | `users.atomic-admin` |
| Keycloak administration, master realm | `atomic-bootstrap` | `bootstrap_password` |

The application also seeds `atomic-viewer`, `atomic-operator` and `atomic-approver`. Their initial passwords are under `users`. This file is not updated when passwords change.

The user menu, sidebar and Settings show the signed-in username. Sign out through the **top-right user icon → Sign out**. Sessions last up to 24 hours; access tokens refresh automatically within that deadline.

For optional live SSO/MCP verification, run:

```sh
.venv/bin/python -m apps.local_identity.verify
```

This checks authentication and reads existing records without executing tests. It uses the original seeded credentials, so adapt it if those passwords/accounts have changed.

## 7. Add hosts and run tests

Before downloading the first agent package, sign in as an administrator and open **Settings → Agent enrollment**. **Initial installation token lifetime (minutes)** defaults to **60**. To change it, enter a whole number from **5 to 1,440**, choose **Save enrollment settings**, and wait for confirmation.

The saved value survives restarts and applies to new Linux/Windows packages and direct enrollment tokens. Install before the expiry shown after download. Changing the setting does not extend an existing token; generate a fresh package to use the new value. Tokens remain single-use. This setting does not change dashboard sessions or enrolled agents' machine credentials. See [the user guide](SYSTEM_GUIDE.md#configure-the-initial-agent-token-lifetime).

Continue in the [user guide](SYSTEM_GUIDE.md):

1. [Import and approve test definitions](SYSTEM_GUIDE.md#import-and-approve-tests).
2. [Register a host, its profiles and agent](SYSTEM_GUIDE.md#add-an-actor).
3. Keep **On demand** selected for new agents. Selectable **Pinned checkout** actors additionally need to [install the matching catalog](SYSTEM_GUIDE.md#install-a-catalog-on-an-enrolled-linux-actor).
4. [Run one approved test](SYSTEM_GUIDE.md#run-a-test) or [queue several](SYSTEM_GUIDE.md#queue-multiple-tests-on-one-actor).

An online actor also needs a healthy compatible profile and approved test definitions/supporting files. Run or Queue prepares the on-demand bundle automatically. New downloads use [on-demand delivery](ON_DEMAND_TEST_DELIVERY.md), with no host catalog pin or Git requirement; pinned-checkout mode needs the exact reviewed host revision. Creating an actor, installing an agent or importing YAML does not by itself make tests executable. Windows installation automatically prepares the pinned Invoke-AtomicRedTeam framework, all-users YAML dependency and module hash before enrollment. Scheduled-task account provisioning remains local. Existing actors with missing dependencies can use the repair helper in a configuration-only ZIP; see [Windows execution prerequisites](WINDOWS_EXECUTION_PREREQUISITES.md). Pinned-checkout packages install their selected imported catalog commit. Follow [Windows packages](AGENT_PACKAGES.md) and [execution identities](EXECUTION_IDENTITIES.md).

## 8. Manage the installation

Create named application accounts in **Settings → User accounts**. Admins can create users, change roles and permanently delete other human users. Password resets and service accounts remain in Keycloak. See [user management](SYSTEM_GUIDE.md#manage-users).

To provision the owned realm's user-management client independently, back up private state and run:

```sh
.venv/bin/python -m apps.local_identity.user_management
```

Restart the runtime after active work finishes. This enables the existing realm's management client without replacing human accounts or unrelated settings. It requires a working bootstrap administrator; see [Keycloak user management](KEYCLOAK.md#dashboard-user-creation) if that administrator has changed.

Keep `artifacts/keycloak` private and out of Git. It holds passwords, environments, SQLite state, browser-session encryption key, signing keys and TLS material. Back up this directory **and Keycloak's PostgreSQL database** together. A public CA copy is safe to distribute; private keys and credentials are not.

For ongoing work:

- [Start/stop and automatic startup](OPERATIONS.md#start-and-stop)
- [Backups, upgrades, address changes and certificate renewal](OPERATIONS.md#backups-upgrades-and-recovery)
- [MCP/Codex connection](CODEX_PLUGIN.md), using the loopback endpoint above
- [Optional per-run permissions](EXECUTION_SETUP.md#optional-per-run-execution-access), managed through the API
- [Custom identity, proxy or infrastructure deployment](DEPLOYMENT.md)

## Troubleshooting

| Problem                                         | Action                                                                                                                                                                                                                    |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux Docker permission denied                  | Sign out and back in after adding the installation account to the Docker group; confirm `docker version` works without sudo. Do not rerun application setup as root.                                                      |
| Linux Python/Node version is too old            | Use Python 3.12+ and load `nvm use 24` for frontend builds; recreate an unprovisioned virtual environment with the intended Python if necessary.                                                                          |
| Linux systemd service fails                     | Check `journalctl -u atomic-control-control-plane`; verify the unit account, absolute paths, private-file ownership, assigned bind address and free ports.                                                                |
| DNS lookup fails                                | Correct DNS/hosts entries on the server and connecting client. Verify the chosen name resolves to the current server IP.                                                                                                  |
| Cannot reach the control plane                  | Check the route, bind address, ports 19443/18443, firewall and allowed source subnet.                                                                                                                                     |
| Certificate verification fails                  | Install the current public CA in the connecting process's trust store; check expiry and the URL hostname. `permitted subtree violation` means the chain's permitted names/addresses need checking against the chosen URL. |
| `atomic-control-ca.crt` not found               | Copy the public certificate first and use its actual path.                                                                                                                                                                |
| Login reports `Invalid parameter: redirect_uri` | Check the exact dashboard or MCP callback in the corresponding Keycloak client; see [OAuth setup](KEYCLOAK.md#oauth-configuration-and-verification).                                                                      |
| Application port already in use                 | Find the existing owner and use its service manager; do not start a second runtime.                                                                                                                                       |
| Initial installation token expired              | Download a fresh enrollment package for the intended actor. If more time is needed, save a longer lifetime in **Settings → Agent enrollment** before generating it.                                                       |
| Agent remains offline                           | Check its service journal, configured hostname URL, certificate trust and enrollment; see [Linux startup](LINUX_AGENT.md#first-heartbeat-after-enrollment).                                                               |
| Online actor has no catalog or healthy identity | Use actor details to configure the catalog and validate profiles. See the [readiness checklist](SYSTEM_GUIDE.md#before-running-a-test).                                                                                   |
| User update is stale or on hold                 | Refresh the account and finish the intended change, or retry the same unconfirmed deletion. See [user management](SYSTEM_GUIDE.md#manage-users).                                                                          |

Installation is ready when health/readiness pass, signed-out visitors see only login, and an administrator can sign in and sign out. An actor is ready after enrollment and profile validation; execution also requires the test's catalog approval and compatible external prerequisites. Pinned-checkout delivery additionally requires its verified revision. Perform an authorized test through the normal UI workflow when you are ready to validate actual execution.
