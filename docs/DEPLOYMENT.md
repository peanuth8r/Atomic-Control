# Deployment

Use the [installation guide](INSTALLATION_GUIDE.md) for a complete macOS or Linux management-host setup and [operations](OPERATIONS.md) for routine service management.

## Management services

The bundled deployment runs Keycloak and its PostgreSQL identity database in Docker. The management host runs the HTTPS API, built React dashboard, packaging worker and MCP adapter. The application database is SQLite, with migrations managed by Alembic. PostgreSQL as the application database requires separate driver and concurrency validation.

| Service           | Bundled listener                       | Clients               |
| ----------------- | -------------------------------------- | --------------------- |
| API/dashboard     | HTTPS 19443 on configured bind address | Browsers and actors   |
| Keycloak          | HTTPS 18443                            | Browsers, API and MCP |
| MCP               | HTTPS 19444 on loopback                | Local MCP clients     |
| Identity database | Docker-internal PostgreSQL             | Keycloak only         |

Use canonical hostnames in the API URL, OIDC issuer and certificates. DNS must resolve from every participating device. Routed actors need a route and outbound verified HTTPS to the API; subnet filtering and firewalls must permit their source networks. Agent hosts need no inbound WinRM, SSH or application listener for job transport. MCP exposure beyond loopback requires an explicitly configured deployment and client-reachable resource URL.

## Application configuration

Keep private environment files, job-signing and session-encryption keys, CA/TLS private keys, databases and identity volumes outside version control. The runtime loads `artifacts/keycloak/application.env` and preserves it across restarts. Use routine Compose/runtime commands rather than setup actions when only restarting: setup actions regenerate the application environment.

Run one API worker. Browser tokens are stored encrypted in durable sessions, but pending OAuth login state and permission previews are process-local. Use a service manager for the application and retain logs in a protected location. Disable access logging of OIDC callback query strings.

A reverse-proxy deployment can run `apps.api.app.main:app` behind TLS and serve the frontend build at the same origin. Preserve the public host, strip untrusted forwarded headers, apply endpoint-appropriate body limits and auth rate limits, and set security headers. Templates are in `deploy/`; compare body limits with catalog/supporting-file upload contracts before applying them. Do not expose a development server as the production API.

Default `ATOMIC_APPROVAL_MODE=catalog` permits compatible operator requests under exact catalog approval. Optional `per_run` additionally uses an administrator-controlled scope policy and separate human approvals. OIDC and RSA job signing are required in either mode.

## Execution hosts

Generate actor-specific packages from **Actors**. Enrollment tokens default to 60 minutes and are single-use, with a 5–1,440-minute administrator setting for future issuance. Package generation does not create local accounts or execute tests.

Windows requires Administrator Windows PowerShell 5.1 and protected all-users Python 3.12+. Its installer verifies HTTPS/CA trust, installs the pinned execution framework/YAML dependency and Python runtime, enrolls and registers `AtomicControlAgent`. `-StartService` starts it after setup. Local administrators provision the execution accounts, batch-logon rights and fixed password-backed tasks. See [Windows packages](AGENT_PACKAGES.md).

Linux requires Python 3.12+, systemd 245+, cgroup v2 and bash/sh. Its installer creates a protected virtual environment, enrolls and registers a disabled/stopped `atomic-control-agent` service. Start it explicitly and let signed profile synchronization validate the existing local accounts. See [Linux setup](LINUX_AGENT.md).

On-demand delivery downloads/removes only the current test and declared files. Per-test external dependencies remain locally provisioned. Selectable pinned-checkout delivery additionally needs Git and a verified clean catalog matching approval. Windows installs a selected checkout through its package; Linux also supports managed catalog installation from actor details.

## Operations and recovery

Monitor `/health`, `/ready`, actor heartbeats, preparation failures and execution holds. `/ready` checks application migration state and preparation availability. The default rotating agent credential lasts 24 hours; actors must reach the API to renew it. Runtime updates preserve installed identity and credentials and require an idle stopped service.

Use SQLite's online backup API for application data and a consistent identity-database backup. Preserve the keys needed to decrypt sessions and verify jobs. Bundle storage grows because historical artifacts are retained for cleanup. Log retention can expire log bodies while preserving audit/identity metadata; see [operations](OPERATIONS.md).

Before rollback or host decommissioning, stop dispatch, verify attempt processes have stopped, resolve uncertain work and preserve evidence. Reconciliation never requeues execution. Actor deletion releases a hostname and preserves history; host uninstallation and local-account removal are separate operations.
