# Catalog sync and YAML uploads

Administrators manage definitions through **Test Catalog**. Importing records test definitions without approving them, executing commands or installing files on actors. Review and approve the intended tests separately.

## Sync from GitHub

1. Choose **Sync from GitHub** and enter an official branch, tag or commit.
2. Choose **Fetch preview**. The server resolves an exact commit from `redcanaryco/atomic-red-team`.
3. Review added, changed, unchanged and removed definitions and cross-source conflicts.
4. Confirm the reviewed import. A changed catalog/approval state requires a fresh preview.

Only the fixed official public repository is accepted. Fetching uses bounded HTTPS/archive processing without payload execution. Imports retain exact revision/source metadata. Changed/removed definitions lose approval; historical run snapshots remain intact. Tests for unsupported platforms remain browsable but cannot execute.

## Upload YAML

Choose **Upload YAML**, select technique files and validate the preview before confirmation. Files must contain valid bounded Atomic technique YAML with unique GUIDs. Duplicate keys, anchors/aliases, executable tags, duplicate filenames and malformed structures are rejected.

Supply the exact source commit for executable definitions. An upload without a pinned revision is catalog-only. Windows PowerShell/Command Prompt and Linux bash/sh definitions can receive approval on matching platforms. Custom files referenced by the test are attached in its **Supporting test files** review controls.

Review commands, prerequisite checks/installers, cleanup, defaults, risk and allowed profile types before choosing **Approve test**. Approval verifies a file plan; Run/Queue builds the bundle automatically. Official assets come from the exact official commit and custom assets are retained centrally. Approved inline tests need no separate file-preparation action. External software prerequisites remain locally provisioned.

## Custom tests from API or chat

Operators can append new unapproved tests using `POST /api/v1/catalog/custom-tests` or `atomic_add_custom_test`. The content-pinned submission requires no Git commit, refuses existing GUIDs and can retain supporting files for administrator review. This does not grant approval or execution. See [custom tests](CUSTOM_TESTS.md).

## API contracts

Paths below use `/api/v1`; import administration is human-administrator-only.

| Endpoint                             | Contract                                                                   |
| ------------------------------------ | -------------------------------------------------------------------------- |
| `POST /catalog/sync`                 | `{ "ref": "master" }`; returns an import ID/status while fetching          |
| `POST /catalog/uploads`              | Technique `{filename, content}` files and optional exact `source_revision` |
| `GET /catalog/imports`               | Recent staged/applied imports                                              |
| `GET /catalog/imports/{id}`          | Paginated preview, counts/status and `preview_token`                       |
| `POST /catalog/imports/{id}/confirm` | Reviewed `preview_token` and deliberate `replace_conflicts` selection      |
| `DELETE /catalog/imports/{id}`       | Discard a pending/failed preview                                           |
| `GET /catalog/source`                | Fixed repository and upload limits                                         |

Preview confirmation is transactional/idempotent and binds staged content plus current catalog/approval state. Ready previews expire after 24 hours. At most five unexpired pending previews and one active GitHub fetch are allowed. See deployed OpenAPI for exact request limits and error schemas.

## Delivery and content changes

On-demand actors download only their current approved test and declared supporting files at execution. They need no host catalog pin. The renderer omits empty optional input arguments; re-approving a test replaces a stale rendered-file plan without rewriting historical bundles.

Selectable pinned-checkout actors need a protected clean local checkout matching the imported revision and definition hashes. Linux provides [managed checkout installation](EXECUTION_SETUP.md#install-and-pin-the-linux-catalog); Windows can install a selected official commit through its package. A catalog import never performs that host installation automatically.
