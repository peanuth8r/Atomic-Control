# Add custom Atomic tests

Operators and administrators can add new custom test definitions through REST or MCP. Submission creates **unapproved** catalog entries. An administrator reviews commands, defaults, risk, profiles and supporting files in **Test Catalog** before execution.

Custom tests use on-demand delivery. Each submission receives a 40-character content-derived revision and full SHA-256 definition/file hashes; the revision is not a GitHub commit. No repository or agent update is required. Submissions cannot replace an existing GUID, change approval or request a run.

## REST endpoint

`POST /api/v1/catalog/custom-tests` requires an authenticated operator and a stable `Idempotency-Key` header. MCP callers additionally need `atomic:request`.

```json
{
  "filename": "T1082-custom.yaml",
  "content": "attack_technique: T1082\ndisplay_name: System Information Discovery\natomic_tests:\n- name: Custom hostname discovery\n  auto_generated_guid: 88c44245-3424-4f62-82d3-5bc4c6cb6068\n  description: Report the hostname on an authorized Windows host.\n  supported_platforms: [windows]\n  executor:\n    name: command_prompt\n    command: hostname\n",
  "files": []
}
```

Use a new GUID for each test. A technique YAML may contain up to 100 tests. `filename` defaults to `custom.yaml`. YAML is bounded to 1 MB and uses the same strict parser as catalog imports. The endpoint accepts no `approved`, risk, profile, command-override or source-revision fields outside the YAML definition.

The [ready-to-use example](examples/custom-hostname.yaml) contains a Windows hostname test. Give each distinct test a new GUID. The [REST reference](API.md#custom-tests) includes a complete request-from-file command, response and error table. For another local YAML file, create the request body without shell-escaping its contents:

```sh
python3 - <<'PY' > /tmp/atomic-custom-request.json
import json
from pathlib import Path
path = Path('T1082-custom.yaml')
print(json.dumps({'filename': path.name, 'content': path.read_text(), 'files': []}))
PY

curl --fail-with-body "$ATOMIC_API_URL/api/v1/catalog/custom-tests" \
  -H "Authorization: Bearer $ATOMIC_ACCESS_TOKEN" \
  -H "Idempotency-Key: custom-hostname-001" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/atomic-custom-request.json
```

Set the deployment URL and a personal OIDC access token for Atomic Control's API audience securely beforehand. Keep HTTPS verification enabled. Reuse the same idempotency key and exact body after a transport failure. Changing a body with that key returns `idempotency_conflict`; another key cannot overwrite an existing GUID. Multi-test submissions are transactional: any conflict/invalid file rejects the entire addition.

The response includes submission ID, `status: submitted`, source/revision kind, submitting identity, created GUIDs and hashes, supporting-file metadata and `replayed`. It is a submission receipt, not execution evidence. Read current test status through `GET /api/v1/tests/{guid}`.

## MCP tool

Use `atomic_add_custom_test` on the existing authenticated Atomic Control MCP endpoint. Arguments are:

| Argument          | Value                                              |
| ----------------- | -------------------------------------------------- |
| `content`         | Atomic technique YAML string                       |
| `idempotency_key` | Stable unique key for this intended submission     |
| `filename`        | Optional safe `.yaml`/`.yml` filename              |
| `files`           | Optional supporting `{path, content_base64}` files |

The connection needs `atomic:read` for its session and `atomic:request` for submission. The tool uses the caller's identity; it grants no administrator rights. Refresh the MCP connection/tool list after deploying this feature. A submission never approves or executes the test. Use `atomic_get_test_details` to inspect its returned GUID; `atomic_list_tests` continues to list approved tests only.

See the [MCP argument/result walkthrough](MCP.md#add-custom-atomic-tests) for a complete tool call and retry handling.

## Supporting files and review

Each supporting file has a unique relative path under `atomics/<technique>/`, for example `atomics/T1082/src/helper.ps1`, plus base64 content. The selected technique YAML is generated automatically and cannot be supplied as a supporting file. Traversal, reserved paths, duplicate/case-colliding paths and file/directory collisions are rejected.

Build supporting-file entries from actual bytes, for example:

```python
import base64
from pathlib import Path

file = {
    'path': 'atomics/T1082/src/helper.ps1',
    'content_base64': base64.b64encode(Path('helper.ps1').read_bytes()).decode('ascii'),
}
# Include this entry in the request's files list when the test needs it.
```

The endpoint allows up to 127 supporting files, 16 MiB per file, within its 24 MB HTTP body limit and the 64 MiB bundle limit. Files remain centrally retained by SHA-256 and are not installed or executed during submission. Missing dependencies can be attached during review.

The test appears in the catalog as **Custom test**. **Supporting test files** shows retained submitted files and their hashes; re-upload is unnecessary unless the reviewer changes content. The normal approval action resolves the reviewed file plan. Run/Queue then performs automatic packaging, verified download and workspace removal under the selected healthy profile.

Content revisions are excluded from host Git-checkout selectors. Use an on-demand actor to execute approved custom tests. External software prerequisites and test cleanup keep their normal separate workflows.
