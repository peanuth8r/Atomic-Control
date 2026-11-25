# Atomic Control Codex connection

The plugin connects to authenticated HTTPS MCP with each person's OIDC identity and supplies local dashboard-link tools. Deployment services run separately. Use one enabled connection to the execution MCP endpoint.

## Packaged plugin

From the repository root, configure explicit URLs for your deployment before installing:

```sh
.venv/bin/python -m scripts.configure_codex_plugin \
  --mcp-url https://localhost:19444/mcp \
  --dashboard-url https://control.example.test:19443
codex plugin marketplace add .
codex plugin add atomic-control@atomic-control-local
```

Substitute the canonical dashboard hostname. The bundled deployment listens for MCP only on loopback, so `localhost` refers to its management host. Remote MCP clients need a separately configured reachable server/resource rather than the local-only URL.

The plugin supplies `atomic_control` for execution MCP and `atomic_control_dashboard` for dashboard links. It stores configured URLs/checkout paths, not tokens or client secrets. Keep its source checkout/runtime available. Sign in through the provider when prompted; refresh the connection or begin a new chat to load its tools/skill as needed.

The configured public OAuth client is `atomic-control-codex`, with callback `http://127.0.0.1:1456/callback` and listener port 1456. Keycloak must allow the exact callback; keep PKCE S256 and trusted HTTPS. Let protected-resource metadata supply the resource audience.

If the plugin is the selected connection, disable a duplicate standalone entry in private `~/.codex/config.toml`:

```toml
[mcp_servers.atomic_control_real]
enabled = false
```

Preserve the plugin's `atomic_control` connection. Do not run duplicate callback listeners or store shared tokens/passwords in plugin configuration.

## Standalone alternative

Use this instead of the packaged execution connection when a native standalone server is desired:

```sh
codex mcp add atomic_control_real --url https://localhost:19444/mcp \
  --oauth-client-id atomic-control-codex
```

Align its private configuration with the deployment's callback:

```toml
[mcp_servers.atomic_control_real.oauth]
client_id = "atomic-control-codex"
callback_url = "http://127.0.0.1:1456/callback"
callback_port = 1456
```

Authenticate with `codex mcp login atomic_control_real --scopes atomic:read,atomic:request`; include `atomic:cleanup` when cleanup access is intended. Use the exact protected-resource audience and registered callback. Keep token-exchange secrets server-side and sign in with the actual user's account.

## Connectivity and discovery

Use a resolvable DNS hostname for the OIDC issuer with matching certificates, JWKS and token-exchange metadata. Every browser/client must reach that issuer. A hosts-file entry affects one device only. A configured URL or saved OAuth credential does not prove that this chat has callable tools: confirm `atomic_list_tests` or `atomic_list_actors` availability and a successful authenticated read.

`Invalid parameter: redirect_uri` requires comparing the active login flow's exact callback with the public client's allowed URI and listener port. After changing configuration, restart the connection and begin a fresh login. Keep passwords/codes in the browser and never disable TLS to work around discovery. See [Keycloak configuration](KEYCLOAK.md#oauth-configuration-and-verification).

## Tools and verification

The local bridge exposes `atomic_dashboard_status` and `atomic_dashboard_start`, which return/open the configured dashboard URL. They do not start, stop or reconfigure deployment processes. Start the runtime through [operations](OPERATIONS.md).

The authenticated execution endpoint supplies the 14 tools documented in [MCP](MCP.md). Catalog mode queues explicitly requested compatible approved tests; per-run mode waits for human approval. Stable idempotency keys prevent duplicate requests. An accepted request is not a successful execution; inspect its evidence and do not replay uncertainty.

Run `.venv/bin/python -m scripts.check_codex_plugin` for non-executing local bridge checks. Actual OAuth/delegation/TLS/roles require the live identity checks and tool reads. See [validation](VALIDATION.md).

To add custom YAML from chat, use `atomic_add_custom_test` with the existing `atomic:request` scope. It creates unapproved catalog entries for administrator review; see [custom submission](CUSTOM_TESTS.md). Refresh the connection to discover the tool after the server update.
