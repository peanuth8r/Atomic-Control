# Connection setup

Use the user's selected real HTTPS connection. The installed plugin supplies `atomic_control`; a separately configured native connection can be named `atomic_control_real`. Prefer an existing working connection and avoid adding another copy for a missing-tools problem. Check the current chat's callable tools separately from installation and saved OAuth status.

For a standalone native connection to this local deployment:

```sh
codex mcp add atomic_control_real --url https://localhost:19444/mcp --oauth-client-id atomic-control-codex
```

Before login, align the server's private Codex configuration with the registered loopback callback:

```toml
[mcp_servers.atomic_control_real.oauth]
client_id = "atomic-control-codex"
callback_url = "http://127.0.0.1:1456/callback"
callback_port = 1456
```

Run `codex mcp login atomic_control_real --scopes atomic:read,atomic:request`; request cleanup scope when needed. Register the exact callback with the public Keycloak client and retain PKCE S256 and issuer verification. Restart the MCP connection after configuration changes and begin a fresh login. Begin a new authorization flow after changing the callback. Let the deployment's protected-resource metadata supply its resource audience; avoid a redundant `oauth_resource` override.

Authentication is completed through the user's provider browser flow. In the desktop app, restart the selected connection under Settings → MCP servers and inspect `/mcp`. Confirm the chat can call `atomic_list_actors` or `atomic_list_tests` before claiming execution readiness. An installed plugin or saved OAuth credential alone does not establish chat tool availability. Never store tokens or shared account credentials in the plugin or bypass a failed real connection.

For the optional skill/dashboard-link plugin, run `scripts.configure_codex_plugin` with explicit `--mcp-url` and `--dashboard-url` HTTPS URLs, then install the configured repository marketplace plugin. The checkout and its virtual environment must remain available. A new chat may be required to load the installed skill. Use one connection method at a time. See `docs/CODEX_PLUGIN.md` and `docs/MCP.md`.
