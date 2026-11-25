# MCP adapter

The adapter uses pinned official Python MCP SDK **2.3.0**, `MCPServer`, Streamable HTTP, `TokenVerifier`, `AuthSettings`, and SDK-provided OAuth protected-resource discovery. It has no broker, shell, account-management, catalog-review or approval tools. Operators can append unapproved custom definitions for human review.

| Tool                           | REST operation                                         | Required scope                  |
| ------------------------------ | ------------------------------------------------------ | ------------------------------- |
| atomic_add_custom_test         | POST /catalog/custom-tests (unapproved new GUIDs only) | atomic:request                  |
| atomic_list_tests              | GET /tests?approved_only=true                          | atomic:read                     |
| atomic_get_test_details        | GET /tests/{guid}                                      | atomic:read                     |
| atomic_list_actors             | GET /actors                                            | atomic:read                     |
| atomic_list_execution_profiles | GET /actors/{id}/profiles                              | atomic:read                     |
| atomic_check_prerequisites     | POST /runs action=check                                | atomic:request                  |
| atomic_request_test            | POST /runs                                             | atomic:request                  |
| atomic_get_execution           | GET /runs/{id}                                         | atomic:read                     |
| atomic_cleanup_test            | POST /runs/{id}/cleanup                                | atomic:cleanup                  |
| atomic_preview_queue           | POST /actors/{id}/queue/preview                        | atomic:read (operator required) |
| atomic_queue_tests             | POST /actors/{id}/queue                                | atomic:request                  |
| atomic_get_queue               | GET /actors/{id}/queue                                 | atomic:read                     |
| atomic_get_batch               | GET /run-batches/{id}                                  | atomic:read                     |
| atomic_control_batch           | POST /run-batches/{id}/{pause,resume,cancel}           | atomic:request                  |

Custom-test and execution submission tools require a caller-supplied stable idempotency key; retry with the same key and inputs after a transport failure. Request/cleanup/check responses retain the REST state: catalog mode queues approved compatible requests immediately (`authorization_source: catalog`), while per-run mode returns `pending_approval`. Use mutation tools only for the user's explicit requested operation. Structured output contains `ok`, `outcome`, `data` or `error`. Never interpret acceptance as execution success.

For bulk requests, paginate discovery to collect the user's exact selected GUIDs, choose one actor/profile, and call `atomic_preview_queue`. Report eligibility/exclusions and submit that selection with the returned `preview_hash` using `atomic_queue_tests`. Preserve order, timeout and the idempotency key on retries. A changed preview requires another preview. Inspect progress with `atomic_get_queue` / `atomic_get_batch` and per-test evidence with `atomic_get_execution`. Batch controls are idempotent commands; they accept `action` of `pause`, `resume` or `cancel` and do not interrupt the active test. The default failure policy is continue after ordinary failures and default lifetime is 24 hours. Human approvals and uncertain-outcome reconciliation remain in the dashboard. See [queue API semantics](API.md#actor-test-queues).

## Add custom Atomic tests

`atomic_add_custom_test` submits one Atomic technique YAML document, with up to 100 new test GUIDs, to the existing authenticated MCP endpoint. It calls `POST /api/v1/catalog/custom-tests` using the delegated caller. The result is an unapproved catalog submission, not an execution request.

Use an operator-capable identity with **`atomic:read` and `atomic:request`**: read is required for the MCP session and request authorizes submission. No new catalog-administrator scope is needed. Refresh the connection/tool list after upgrading the server if the tool is missing. The [Codex connection guide](CODEX_PLUGIN.md) covers authentication and discovery.

### Arguments and example

| Argument          | Required | Meaning                                                                    |
| ----------------- | -------- | -------------------------------------------------------------------------- |
| `content`         | Yes      | Full Atomic technique YAML string; the tool does not fetch a file path/URL |
| `idempotency_key` | Yes      | Stable 1–128-character key for this intended submission                    |
| `filename`        | No       | Safe YAML filename; default `custom.yaml`                                  |
| `files`           | No       | Up to 127 `{path, content_base64}` supporting files; omit or use `[]`      |

For the [same YAML example used by REST](examples/custom-hostname.yaml), the tool arguments are:

```json
{
  "content": "attack_technique: T1082\ndisplay_name: System Information Discovery\natomic_tests:\n  - name: Custom hostname discovery\n    auto_generated_guid: 88c44245-3424-4f62-82d3-5bc4c6cb6068\n    description: Report the hostname on an authorized Windows host.\n    supported_platforms:\n      - windows\n    executor:\n      name: command_prompt\n      command: hostname\n",
  "idempotency_key": "custom-hostname-001",
  "filename": "custom-hostname.yaml",
  "files": []
}
```

Use a new GUID for a distinct test and keep the original arguments/key for a retry. An optional file entry looks like `{ "path": "atomics/T1082/src/note.txt", "content_base64": "Zml4dHVyZQ==" }`. File paths must stay under the YAML's technique directory. The full [REST limits and errors](API.md#supporting-files-and-limits) apply, including YAML/file sizes and encoded request-body overhead.

### Result and next steps

1. Check `ok`. Successful structured output has `ok: true`, `outcome: submitted` and `data` containing the [submission receipt](API.md#submission-receipt).
2. Retain `data.id`, `data.revision`, the returned test GUIDs/hashes and the idempotency key. `data.submitted_by` remains the original caller.
3. Inspect a new unapproved test with `atomic_get_test_details` using its GUID. `atomic_list_tests` lists approved tests only, so a new submission will not appear there yet.
4. A human administrator opens the test in **Test Catalog**, reviews commands/defaults/cleanup and supporting files, chooses risk/profile permissions and clicks **Approve test**. Retained files do not need re-uploading.
5. After approval, use normal discovery and an explicitly requested execution/queue workflow on an on-demand actor. Submission does not select an actor, grant permission or run a test.

The server assigns an immutable content-derived revision, not a GitHub commit, and keeps supporting files centrally. Approved custom tests work with the current on-demand agent protocol. Host Git-checkout selection does not apply to their content revisions.

### Retry and failure behavior

For a transport failure, repeat the **same tool call with the same key and exact inputs**. A successful retry returns the same receipt with `replayed: true`. If `ok: false`, inspect `error.code`: `idempotency_conflict` means the body changed for an existing key, `custom_guid_conflict` means a GUID already exists, and `insufficient_scope` means the connection lacks request scope. Argument/schema errors can also be returned as tool errors before REST submission.

Do not change the key merely to work around a lost acknowledgement or GUID conflict. The endpoint cannot overwrite existing definitions, approve submissions, provision identities or execute content. An administrator handles changes to existing definitions through normal catalog review/import. Execution/check/cleanup and batch requests retain their own idempotency keys and authorization.

## Configuration

Configure an OIDC issuer with RS256 JWT access tokens and trusted JWKS. MCP resource audience must exactly match `ATOMIC_MCP_RESOURCE`, including `/mcp`. Configure the public resource URL behind TLS, issuer, JWKS, API URL and an IdP RFC 8693 token-exchange endpoint/client using `.env.example`.

Run:

```sh
.venv/bin/python -m apps.mcp.server
```

This binds loopback port 8001; terminate TLS at a reverse proxy and forward `/mcp` plus `/.well-known/oauth-protected-resource/mcp`. Unauthenticated HTTP requests fail before tool parsing. `atomic:read` is required for a session and mutation scopes are checked per tool.

The incoming MCP token is **not** forwarded to the API as though its resource audience matched. Instead, the adapter exchanges it for an API-audience delegated token. Configure the identity provider to preserve the original `sub`, include the constrained `atomic:*` scopes, refuse privilege expansion, and identify the adapter in `azp`. Put that client ID in the API's `ATOMIC_MCP_CLIENT_IDS`. The API independently verifies its audience and reduces MCP callers to read/request/cleanup rights, regardless of administrator role claims. In optional per-run mode it also applies per-subject actor/profile/test/risk grants; catalog mode uses the approved definition and permitted profile types as standing authorization.

If the provider does not support constrained token exchange, this adapter will fail closed; configure provider support before deployment. There is no generic service-token fallback. Local Keycloak token exchange has been verified; other providers require their own acceptance checks.

SDK in-memory test clients bypass HTTP authentication by design. Tests separately verify the HTTP 401 and discovery boundary. Official references: [SDK authorization](https://py.sdk.modelcontextprotocol.io/run/authorization/) and [SDK installation](https://py.sdk.modelcontextprotocol.io/get-started/installation/).

## Codex desktop plugin

The Codex plugin provides dashboard links and connects directly to this authenticated HTTPS MCP adapter. Each caller signs in with their own OIDC identity; no shared service identity is used. See [Codex plugin setup](CODEX_PLUGIN.md).

Testing reasons are optional for `atomic_request_test`, `atomic_check_prerequisites` and `atomic_queue_tests`. Omit `reason` when none was supplied; do not invent a justification or ask solely to fill this field. Cleanup keeps its required reason. All requests still need a stable idempotency key.
