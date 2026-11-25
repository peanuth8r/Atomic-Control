# Keycloak deployment

Use the [installation guide](INSTALLATION_GUIDE.md) for a fresh management host and [operations](OPERATIONS.md) for service management. The bundled profile runs digest-pinned Keycloak/PostgreSQL containers with a separate host-run HTTPS API/dashboard and MCP. The application database is SQLite. Network configuration determines the public hostnames; MCP is loopback-only by default.

## Accounts and private files

Generated secrets live under private, Git-ignored `artifacts/keycloak`. Read `credentials.json` privately for initial passwords; it is not updated after provider password changes.

| Account            | Purpose                                        |
| ------------------ | ---------------------------------------------- |
| `atomic-admin`     | All application roles, including administrator |
| `atomic-operator`  | Viewer and operator                            |
| `atomic-approver`  | Viewer, approver and privileged approver       |
| `atomic-viewer`    | Read access                                    |
| `atomic-bootstrap` | Keycloak master-realm bootstrap administration |

Dashboard users choose **Sign in with SSO**. The initial application passwords are under `users`; the bootstrap password uses `bootstrap_password`. Application administration and Keycloak realm administration are separate roles. Protect the generated environment, database, browser-session key, signing keys, TLS/CA keys and identity volumes. Share only the public CA certificate.

## Start and stop

Initial provisioning, with Docker running and the frontend built:

```sh
.venv/bin/python -m apps.local_identity.setup up
.venv/bin/python -m apps.local_identity.runtime
```

The runtime loads the existing private environment, applies migrations and starts API/dashboard plus MCP. It refuses occupied ports. Ctrl+C stops the application processes, not the identity containers or host agents.

Use [routine Compose commands](OPERATIONS.md#start-and-stop-manually) for container start/stop/status. **Every setup-helper action regenerates `application.env`**, including status/stop/provision. Preserve and reapply intentional overrides whenever using setup. Setup validates ownership of its realm and preserves existing accounts/passwords; it is not a routine restart command.

## HTTPS trust

The local CA signs constrained service certificates. Service certificates last 90 days and the CA certificate 365 days; renewal is manual. Preserve private keys/state and follow [certificate renewal](OPERATIONS.md#renew-local-certificates).

Trust `artifacts/keycloak/atomic-control-ca.crt` on management/browser clients and actors. Compare its fingerprint privately with the intended server:

```sh
openssl x509 -in artifacts/keycloak/atomic-control-ca.crt -noout -fingerprint -sha256
```

The [installation guide](INSTALLATION_GUIDE.md#4-trust-the-public-ca) gives macOS, Linux and Windows trust commands. Windows agent packages can include/import the explicit public root for the machine before verified HTTPS. Linux transport uses system CA trust. Browser trust alone does not configure every service environment. Keep certificate verification enabled and distribute no private keys.

## OAuth configuration and verification

Browser authentication uses authorization code/PKCE, state and nonce and stores encrypted tokens server-side. Sessions default to a fixed 24 hours. The owned realm maps the application roles and configures API audience plus constrained caller-preserving MCP token exchange. User-management credentials are a separate protected server-side client.

The public Codex client is `atomic-control-codex`. Registered local callbacks include `http://127.0.0.1:1456/callback` for the plugin/native connection and the separate verification callback `http://127.0.0.1:1455/oauth/callback`. Keep exact callback URLs, listener ports and PKCE S256 aligned. Anonymous dynamic client registration is not enabled. See [Codex setup](CODEX_PLUGIN.md).

Run `.venv/bin/python -m apps.local_identity.verify` for the bundled identity checks with the runtime/containers running. The harness uses initial seeded accounts; adapt it when credentials have changed. Live browser checks are opt-in and block application mutations. These checks do not execute tests on actors.

## Local subnet access

Reserve a stable management-host address and configure DNS for every browser client and actor. On an idle backed-up deployment, configure the intended address/source subnet and canonical hostnames:

```sh
.venv/bin/python -m apps.local_identity.setup network \
  --address 10.20.30.10 --subnet 10.20.30.0/24 \
  --public-hostname control.example.test \
  --identity-hostname control.example.test
.venv/bin/python -m apps.local_identity.setup up
```

Replace the examples. Setup publishes the API at `https://control.example.test:19443` and issuer at `https://control.example.test:18443/realms/atomic-control`. DNS names must be included in certificate constraints/SANs and resolve on all devices. API subnet filtering ignores forwarded-IP headers; routed networks also need matching routes, subnet allowance and firewall rules. Keycloak has separate network exposure, and PostgreSQL is not published. MCP remains `https://localhost:19444/mcp` for local clients.

Stop runtime/identity containers before network reconfiguration, preserve private state, update DNS/firewalls, reapply custom environment settings and refresh CA trust where changed. Then restart and verify HTTPS, sign-in and agent heartbeats. Use `network --loopback` for a host-only deployment; remote actors cannot reach that profile.

### Use a DNS hostname for native Codex OAuth

Use a stable DNS hostname for the issuer and public API rather than an address literal. Keep those hostnames when changing the server address; pass both hostname flags on subsequent network configuration. Update DNS and matching certificate material, not every client URL, when only the address changes.

A hosts-file mapping applies only to that device. Internal DNS is preferable for multiple devices. If changing the actual hostname/issuer, update provider callbacks/origins, API/MCP settings, DNS/trust and affected agent URLs through reviewed configuration maintenance, then sign in again. See [address changes](OPERATIONS.md#change-the-lan-address).

### Use the hostname for the dashboard and agents

Use the same configured canonical API URL for browser access, package generation and agents. Certificates must permit that name. The loopback MCP URL is separate and should match its protected-resource metadata. Never change an enrolled actor's UUID or replace its credential file when correcting connectivity; use configuration-preserving maintenance.

## Dashboard user creation

Human administrators manage application accounts in **Settings → User accounts**. The API's protected Keycloak client supplies management access; no bootstrap credential is sent to the browser or MCP. New accounts receive supported application roles and a temporary password requiring change at first sign-in. Password resets and service accounts stay in Keycloak administration.

`ATOMIC_USER_MANAGEMENT_PROVIDER=keycloak` and the management client ID/secret must be configured server-side. Bundled `setup up` provisions this client. To configure it independently in the owned realm, use `.venv/bin/python -m apps.local_identity.user_management` with working bootstrap administration and restart the idle application. Preserve unrelated private settings and accounts.

### Dashboard role editing

Administrators edit supported direct application roles for another human user. Current account versions prevent stale changes. Self/group/composite/custom-role changes are refused. Target sessions/access are revoked; the user signs in again. An incomplete provider update keeps access held until administrator reconciliation.

### Dashboard user deletion

Deletion confirms the exact username/version, removes the provider account and keeps its subject blocked. Self and service-account deletion are refused. Execution/audit history remains. A new account can reuse the username with a new subject. See [user management](SYSTEM_GUIDE.md#manage-users).
