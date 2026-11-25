# REST API

FastAPI's `/openapi.json` and `/docs` on the running deployment define authoritative schemas. Application routes use `/api/v1`; health/readiness and browser `/auth/*` routes are outside that prefix. This reference groups supported workflows rather than duplicating every schema.

## Authorization

Human clients use OIDC identities and application roles. Default `ATOMIC_APPROVAL_MODE=catalog` queues compatible operator requests under exact catalog approval, returning `authorization_source: catalog` and retaining the catalog reviewer. Optional `per_run` additionally requires exact subject grants and human approval. Elevated per-run approval requires a separate privileged approver.

Execution-access administration uses `GET /execution-access`, `POST /execution-access/preview` and `POST /execution-access/apply` in per-run mode with a protected policy file. Previews are caller-bound, single-use, expire after five minutes and reject changed policy/targets. Grants bind exact subject, actor, profile, test, risk and action without wildcards. These endpoints do not execute or approve tests.

MCP uses delegated caller tokens reduced to read/request/cleanup. It cannot use human-only administration, catalog-review, approval or reconciliation operations.

## Endpoint groups

Paths in this table use the `/api/v1` prefix.

| Group                                   | Methods and paths                                                                                                                                                                               |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Identity                                | `GET /me`                                                                                                                                                                                       |
| Catalog                                 | `GET /techniques`, `GET /tests`, `GET /tests/{guid}`, `POST /tests/{guid}/review`, `POST /tests/{guid}/revoke`                                                                                  |
| Imports                                 | `GET /catalog/source`, `GET /catalog/imports`, `POST /catalog/sync`, `POST /catalog/uploads`, `GET /catalog/imports/{id}`, `POST /catalog/imports/{id}/confirm`, `DELETE /catalog/imports/{id}` |
| [Custom test submission](#custom-tests) | `POST /catalog/custom-tests` — submit new unapproved Atomic YAML and supporting files                                                                                                           |
| Actors                                  | `POST /actors`, `GET /actors`, `GET /actors/{id}`, `POST /actors/{id}/enable`, `POST /actors/{id}/disable`, `POST /actors/{id}/retire` (permanent deletion)                                     |
| Profiles                                | `GET /actors/{id}/profiles`, `POST /actors/{id}/profiles`, `DELETE /actors/{id}/profiles/{profile_id}`, `POST /actors/{id}/profile-sync`                                                        |
| Packages                                | `GET /agents/package-options`, `POST /actors/{id}/agent-package`, `POST /enrollment-tokens`                                                                                                     |
| Runs                                    | `POST /runs`, `GET /runs`, `GET /runs/{id}`, `GET /runs/{id}/logs`, `POST /runs/{id}/cancel`, `POST /runs/{id}/cleanup`, `POST /runs/{id}/reconcile`, `POST /runs/{id}/retry-preparation`       |
| Queues                                  | `POST /actors/{id}/queue/preview`, `POST /actors/{id}/queue`, `GET /actors/{id}/queue`, `GET /run-batches/{id}`, `POST /run-batches/{id}/{pause,resume,cancel}`                                 |
| Per-run approval                        | `GET /approvals`, `POST /runs/{id}/approve`, `POST /runs/{id}/reject`                                                                                                                           |
| Users                                   | `GET /admin/users/options`, `GET /admin/users`, `GET /admin/users/{id}`, `POST /admin/users`, `POST /admin/users/{id}/roles`, `DELETE /admin/users/{id}`                                        |
| Settings/audit                          | `GET /admin/agent-settings`, `PUT /admin/agent-settings`, `GET /audit`                                                                                                                          |
| Checkout catalogs                       | `GET /actors/{id}/catalog-options`, `POST /actors/{id}/catalog-install`                                                                                                                         |

Test/actor/run/audit lists support bounded `limit`/`offset` pagination. Test filters include `q` and `approved_only`; run filters include `status` and `batch_id`. User/import endpoints have their own schema-defined bounds. `/me` returns immutable subject, verified username when available and effective roles/scopes.

## Request and approval

`POST /runs` requires operator authorization and a stable `Idempotency-Key`:

```json
{
  "atomic_guid": "11111111-1111-4111-8111-111111111111",
  "actor_id": "registered-actor-uuid",
  "execution_profile_id": "registered-profile-uuid",
  "action": "execute",
  "timeout_seconds": 120,
  "reason": ""
}
```

Actions are `execute` or `check`; timeout is 10–600 seconds. Reasons are optional, trimmed and limited to 2,000 characters. Null/omitted/blank execution and queue reasons normalize to an empty string. Responses reflect authorization state: catalog mode queues, while per-run mode waits for approval. HTTP 201 records a request and does not establish execution success.

Approval/rejection, cancellation, cleanup and reconciliation use required reasons from their schemas. Cleanup also requires an idempotency key and original execution linkage. Per-run dispatch approval defaults to 30 minutes. Reconciliation is administrator-only, preserves the outcome and never schedules a retry.

Idempotency binds caller, key and exact inputs. Reuse the same key after a transport failure; changed inputs with that key are refused. Snapshots and approval hashes remain immutable.

## Catalog and files

Catalog review supplies exact `content_sha256`, `source_revision`, allowed profile types and risk. The review resolves a file plan from the selected definition, exact official commit and supporting-file hashes. Custom files use bounded `{path, content_base64}` values; `asset_paths` can specify reviewed supporting paths. Approval builds no ZIP and runs no command. An approved inline definition without supporting-file references is packaged automatically under its exact catalog review.

The renderer omits an empty optional `input_arguments` field. Re-approval generates a new plan when the rendered YAML differs from cached content. Historical plans, artifacts and run bindings are preserved. Changed/removed definitions or explicit revocation block new dispatch.

`GET /tests/{guid}/artifact` exposes available file metadata and suggested paths. Normal Run/Queue prepares the approved files automatically. See [imports](CATALOG_IMPORTS.md) and [delivery](ON_DEMAND_TEST_DELIVERY.md).

## Custom tests

Use **`POST /api/v1/catalog/custom-tests`** to add new custom Atomic definitions without a GitHub commit. It accepts one technique YAML document and optional supporting files. A submission creates unapproved entries and no execution request; an administrator reviews them in **Test Catalog** before they can run.

### Authentication and request

Use a personal OIDC access token issued for Atomic Control's API audience and a user with operator permission. The bundled administrator role preset includes that permission. Delegated MCP callers need `atomic:request`. HTTPS remains verified.

| Field/header                | Required | Meaning                                                                     |
| --------------------------- | -------- | --------------------------------------------------------------------------- |
| `Authorization: Bearer ...` | Yes      | Personal API access token                                                   |
| `Idempotency-Key`           | Yes      | Nonblank key, 1–128 characters, retained for retries                        |
| `content`                   | Yes      | Atomic technique YAML text, not a file path or URL                          |
| `filename`                  | No       | Safe `.yaml`/`.yml` filename, at most 128 characters; default `custom.yaml` |
| `files`                     | No       | Supporting `{path, content_base64}` files; default `[]`                     |

Start with the [downloadable YAML example](examples/custom-hostname.yaml), assign a new test GUID when creating a distinct test, and prepare a request from the repository root:

```sh
export ATOMIC_API_URL='https://control.example.test:19443'
# Set ATOMIC_ACCESS_TOKEN securely from your OIDC login.
python3 - <<'PYTHON' > /tmp/atomic-custom-request.json
import json
from pathlib import Path
source = Path('docs/examples/custom-hostname.yaml')
print(json.dumps({
    'filename': source.name,
    'content': source.read_text(encoding='utf-8'),
    'files': [],
}))
PYTHON

curl --fail-with-body "$ATOMIC_API_URL/api/v1/catalog/custom-tests" \
  -H "Authorization: Bearer $ATOMIC_ACCESS_TOKEN" \
  -H 'Idempotency-Key: custom-hostname-001' \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/atomic-custom-request.json
```

Replace the URL and use a fresh idempotency key for each distinct intended submission. Unknown top-level fields, including approval, risk, profile, actor and source-revision fields, are refused. Use the separate review/execution workflows for those operations.

### Submission receipt

HTTP **201 Created** returns this shape. IDs, hashes, subject and timestamp below are illustrative; the content hashes/revision correspond to the supplied YAML example and filename.

```json
{
  "id": "f4e7264c-839b-4a88-b13b-050f780c90c8",
  "status": "submitted",
  "source": "custom",
  "revision": "fa7158be810b6526ec569a3b5bd8afc52bbc8e7d",
  "revision_kind": "content",
  "submitted_by": "example-oidc-subject",
  "created_at": 1795536000.0,
  "tests": [
    {
      "guid": "88c44245-3424-4f62-82d3-5bc4c6cb6068",
      "name": "Custom hostname discovery",
      "technique": "T1082",
      "content_sha256": "3e17682977d40fbc9f5b26d00fb7bf03ed66f79ed2a04d6999a31dee96a8e95d"
    }
  ],
  "files": [],
  "replayed": false,
  "next_step": "Review and approve the submitted tests in Test Catalog before execution."
}
```

`status: submitted` records catalog creation, not approval or execution. `revision_kind: content` identifies a server-generated 40-character content revision rather than a Git commit. Definition/file SHA-256 hashes bind the reviewed content. `submitted_by` is the authenticated caller, including through MCP delegation.

Read the current definition and approval state using `GET /api/v1/tests/{guid}`. `GET /api/v1/tests/{guid}/artifact` includes `submitted_files` metadata and suggested asset paths for the review UI. The receipt is historical; replaying it never resets an approval made after submission.

### Supporting files and limits

Attach each supporting file as `{ "path": "atomics/T1082/src/helper.ps1", "content_base64": "..." }`, using the actual file's base64 bytes. Paths must be unique, canonical and under the submitted technique's directory. The generated `atomics/T1082/T1082.yaml` is included automatically. Absolute/traversing/reserved paths, case collisions and file/directory collisions are rejected.

| Limit                           | Value                                                      |
| ------------------------------- | ---------------------------------------------------------- |
| Technique documents per request | 1                                                          |
| Tests in the document           | 100 maximum, each with a new GUID                          |
| YAML content                    | 1,000,000 UTF-8 bytes maximum                              |
| Supporting files                | 127 maximum                                                |
| Individual supporting file      | 16 MiB maximum                                             |
| Encoded HTTP request body       | 24,000,000 bytes maximum, including base64/JSON overhead   |
| Resulting bundle                | 64 MiB bound, including generated content/archive overhead |

Submitted files are retained by hash and displayed for administrator review; they are not installed during submission. Missing files can be attached during review. See [supporting-file examples](CUSTOM_TESTS.md#supporting-files-and-review).

### Retries, conflicts and errors

Reuse the **same caller, idempotency key and exact body** after a lost acknowledgement or transport failure. A successful repeat returns HTTP 201 with the original receipt and `replayed: true`. It creates no second submission and never overwrites/revokes existing content. Changing the key does not permit reusing an existing test GUID.

| HTTP | Code                                       | Action                                                                                     |
| ---- | ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| 401  | `unauthenticated`, `invalid_token`         | Authenticate with a valid API access token                                                 |
| 403  | `forbidden`, `insufficient_scope`          | Use the intended operator identity/scope                                                   |
| 409  | `idempotency_conflict`                     | Preserve the original body/key for its retry; use a new key only for a distinct submission |
| 409  | `custom_guid_conflict`                     | Existing GUIDs cannot be replaced through submission; assign new GUIDs                     |
| 409  | `custom_source_corrupt`                    | Investigate retained-source integrity before retrying                                      |
| 413  | `body_too_large`                           | Reduce the encoded request size                                                            |
| 422  | `validation_error`, `idempotency_required` | Correct request fields/header                                                              |
| 422  | `invalid_atomic_yaml`, `custom_test_limit` | Correct YAML/schema or reduce the test count                                               |
| 422  | `invalid_custom_file`                      | Correct file paths, base64, collisions or file/bundle size                                 |

The operation is transactional: an invalid test/file or a conflicting GUID rejects the entire addition. To revise an existing definition, an administrator uses the reviewed catalog import workflow; MCP submission cannot replace it.

After submission, an administrator chooses risk/allowed profiles and **Approve test** in Test Catalog. Then request or queue it on a healthy on-demand actor. Content revisions are excluded from Git-checkout selectors. Catalog/per-run mode governs that later execution; neither mode automatically approves a custom submission. See the [MCP workflow](MCP.md#add-custom-atomic-tests) and [custom-test guide](CUSTOM_TESTS.md).

## Agent downloads and enrollment settings

`POST /actors` reserves a hostname/platform and actor UUID in `pending_enrollment`; it does not make a host online. Package generation returns an actor-specific ZIP, checksum/mode headers and enrollment expiry when included. `delivery_mode` defaults to `on_demand`; `checkout` additionally selects an imported catalog revision. Source files are allowlisted and private server files are excluded.

Initial packages use a single-use actor/hostname/platform-bound token. Configuration-only packages contain no installation token and support signed runtime updates. Successful replacement enrollment revokes prior transport credentials; package download alone does not. Replacement requires a disabled actor with no active/uncertain work.

`GET/PUT /admin/agent-settings` is human-administrator-only. PUT accepts `{"enrollment_token_minutes":60}`, an integer from 5 to 1,440. Default 60 is persisted and affects future token/package issuance only. Package options expose the current lifetime; existing token expirations do not change.

Windows packages can include the explicitly configured single public CA. Installer validation binds its hash/fingerprint to the package and imports it to `LocalMachine\Root` before verified HTTPS. Initial Windows setup installs/verifies its framework before enrollment and can start the service with `-StartService`. Linux packages use the host's trusted CA store.

## Profiles and deletion

Profiles bind `profile_key`, display name, local account, `expected_sid` and privilege. Windows uses actual local SIDs. Linux uses `uid:N`; `standard-user` requires nonzero UID, while `local-admin` requires UID 0 and an elevated root identity. Identity bindings and IDs are immutable.

Actor profile synchronization exposes generation, capability/status and bounded per-profile identity results. Register/delete queues desired changes for capable agents; `POST /actors/{id}/profile-sync` retries validation. Agents poll signed allowlisted metadata and report receipts bound to actor, generation and payload hash. Local accounts/passwords/task actions are not transmitted in the manifest. Health requires platform-appropriate kernel/token evidence.

Profile deletion cancels waiting work and preserves immutable execution history. Actor deletion uses `POST /actors/{id}/retire` with exact `hostname` confirmation and optional `reason`; it permanently removes registration/profiles/credentials/enrollment, cancels waiting work and releases the hostname. Both refuse active/uncertain work and applying changes. Deletion is idempotent against the original UUID and cannot target a replacement by reused hostname. Host files/accounts are separate local administration.

## Actor test queues

Preview one actor/profile with ordered `atomic_guids` (up to 500), then submit the reviewed eligible selection with `preview_hash`, timeout, name, optional reason and `Idempotency-Key`. A changed selection/target needs a fresh preview. Preview reports exclusions and grants no execution.

Single requests and batches share durable actor FIFO positions. One item executes at a time. Batch controls pause/resume/cancel remaining work without interrupting the active item; active cancellation is separate. Default policy is `continue` after ordinary failures; selectable `pause` holds later work. Authorization/integrity/identity and uncertain outcomes still block dispatch. Default queue lifetime is 24 hours.

## Automatic central preparation

Approved file plans can queue without a prebuilt archive. A durable worker builds/reuses the immutable bundle when the request reaches the queue head. `preparation` exposes worker progress; `execution_artifact` exposes the separate sealed dispatch binding. The original request snapshot/hash is unchanged.

`ATOMIC_ARTIFACT_WORKER_ENABLED=true` enables normal packaging. Build and actor-download preparation deadlines each default to 300 seconds, separately from execution timeout. Worker leases/retries/cache state survive restarts; readiness reports unavailable preparation.

`preparation_failed` is a pre-execution terminal state with no fabricated result. `POST /runs/{id}/retry-preparation` requires operator authorization, reason and idempotency key and creates a new request only if no actor attempt began. Historical content is reconstructed only when bytes match its approved manifest.

## Agent contract

Agent identity derives only from its credential. Enrollment/heartbeat platform and hostname must match the actor. On-demand heartbeats advertise `delivery_mode: on_demand` and `artifact_protocol: 1`.

| Operation                | Endpoint                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------- |
| Enroll/rotate/heartbeat  | `POST /agents/enroll`, `/agents/credentials/rotate`, `/agents/heartbeat`              |
| Claim/renew/result       | `POST /agents/jobs/claim`, `/agents/jobs/{id}/heartbeat`, `/agents/jobs/{id}/result`  |
| Download                 | `GET /agents/jobs/{id}/artifact` with actor credential and assignment's `X-Job-Grant` |
| Ready                    | `POST /agents/jobs/{id}/ready`                                                        |
| Workspace receipt        | `POST /agents/jobs/{id}/workspace`                                                    |
| Profile synchronization  | `POST /agents/profile-sync/poll`, `/agents/profile-sync/{id}/result`                  |
| Checkout synchronization | `POST /agents/catalog-install/poll`, `/agents/catalog-install/{id}/result`            |

Claim returns `job: null` or a signed assignment with run/attempt IDs, fence and lease. Renewals, readiness, workspace receipts and results require current attempt/fence. Workspace status is distinct from execution status; removal holds persist until purged or explicitly reconciled. Preparation/download grants cannot authorize execution. All tokens retain issuer, audience, signature and time checks.

Results include bounded stdout/stderr, timestamps, exit status and actual Windows token or Linux UID/GID/capability evidence. Identity mismatch or nonzero exit cannot establish success. Duplicate identical results are accepted; conflicting/stale results are refused. Uncertain execution never replays automatically.

## Human-user administration

User creation uses an idempotency key, username, optional profile fields, supported access level and temporary password. Keycloak enforces its password policy; the application minimum is 12 characters. The adapter verifies exact application roles before enabling the new account. Passwords are not returned or persisted by Atomic Control.

Role edits accept a supported `access_level` and current `expected_version`. They change only supported direct application roles and reject stale/self/group/composite/custom-role edits. User deletion requires exact `confirm_username` and current version and rejects self/service-account deletion.

Before mutation, access is held and local sessions removed. Successful edits revoke old access and require fresh sign-in. Uncertain provider completion remains held for administrator reconciliation; deletion retains the subject hold. Account-update leases serialize changes. History keeps the original subject and no previously authorized run is implicitly cancelled. Password resets and service accounts remain in Keycloak.

## Errors and system endpoints

Errors use `{"error":{"code":"actor_offline","message":"Actor is offline or unhealthy"}}`. Validation errors omit raw credential input. Typical codes include `unauthenticated`, `forbidden`, `test_unapproved`, `profile_unavailable`, `catalog_mismatch`, `actor_offline`, `idempotency_conflict`, `stale_lease`, `lease_expired`, `invalid_state` and `result_conflict`.

`GET /health` reports liveness; `GET /ready` checks readiness. Browser routes include `/auth/config`, `/auth/login`, `/auth/callback` and `POST /auth/logout`. Authenticated API permissions are enforced independently of dashboard visibility.
