# On-demand test delivery

**On demand — download only the current test** is the default agent delivery mode. The control plane retains catalog definitions, approved source files and immutable bundles. An actor downloads the selected test and its declared supporting files for one attempt, verifies them and removes the attempt's files after processes stop. No full host checkout or Git installation is required.

## Approve, run or queue

1. Import an exact source revision through GitHub sync or YAML upload.
2. In test details, inspect the commands, prerequisites, cleanup, defaults, risk and allowed profiles. Use **Supporting test files** to review dependencies and attach custom files when needed.
3. Choose **Approve test**. This records the exact definition and immutable supporting-file plan; it does not execute a test or build a ZIP. An approved inline test without external file references uses its exact catalog approval automatically.
4. Request a single test or queue selected tests. When it reaches the actor's FIFO head, the control plane automatically builds or reuses its approved bundle.
5. The actor downloads/verifies the bundle, obtains a separate execution grant, runs the authorized action, removes downloaded files and reports evidence.

There is no separate manual file-preparation step. Jobs carry their own exact source revision and bundle identity, so one actor queue can include several revisions.

Official supporting files come from the exact official GitHub commit. Custom supporting files are retained centrally after upload. Dynamic paths must resolve to a bounded explicit file list. Bundles allow at most 128 regular files, 16 MiB per file and 64 MiB overall. Custom review uploads are additionally bounded by the API's 24 MB body limit.

The YAML renderer omits an empty optional `input_arguments` mapping. If a cached bundle is rejected for empty inputs, click **Approve test** again to generate a corrected plan. Earlier bundles and execution bindings remain unchanged.

## Actor requirements

Register the actor, select **On demand** when generating its package, and complete platform installation, local account/task provisioning, HTTPS trust and profile validation. Each actor needs a healthy execution profile, rather than a host catalog pin.

Windows setup installs the pinned Invoke-AtomicRedTeam framework and its YAML dependency before enrollment. Linux needs its supported shells/systemd environment. Per-test operating-system tools and external prerequisites must be provisioned separately. Prerequisite checks execute reviewed check commands but install no dependencies.

Payloads are readable/executable by the selected profile and protected against its writes. Tests that need to modify packaged source files are unsupported. See [Windows installation](AGENT_PACKAGES.md), [Linux installation](LINUX_AGENT.md) and [profile setup](EXECUTION_SETUP.md).

## Preparation and queue behavior

The durable packaging worker runs with the API when `ATOMIC_ARTIFACT_WORKER_ENABLED=true`. Central preparation uses its own persisted owner lease, retry count, deadline and cache record, with a 300-second default build deadline (`ATOMIC_ARTIFACT_BUILD_SECONDS`). Concurrent requests for the same plan share a build. Restarted workers reclaim expired packaging work.

Preparing work retains its FIFO position without holding an actor execution lease. Pausing holds later work; cancelling a preparing request cannot launch an actor attempt even if its cache build completes. Bounded operational failures retry with backoff. Exhausted preparation failures follow the batch Continue/Pause policy, which defaults to continuing after ordinary failures. Integrity or authorization failures hold dispatch.

**Retry preparation** creates a new audited request at the queue tail only when the original has no actor attempt. It preserves the failure record. Per-run approval mode applies its normal approval requirements to that request.

Actor download/verification has a separate 300-second default deadline (`ATOMIC_ARTIFACT_PREPARATION_SECONDS`) and renews its attempt lease. Execution timeout starts after preparation. Only pre-execution transfers may retry automatically.

## Workspace removal and cleanup

**Downloaded files removed** covers the bundle, temporary payload workspace and disposable attempt output. It does not reverse the test's changes elsewhere on the host. **Run test cleanup** is a separate authorized request.

Cleanup downloads the original retained bundle even after the active catalog changes. Its approval must remain valid and its original actor/profile must exist. Catalog revocation also revokes the relevant historical file approvals. A replacement actor sharing a hostname receives none of the original identity's cleanup rights.

The database retains immutable bundle bytes for historical cleanup and evidence without automatic artifact garbage collection. Include artifact growth in capacity planning and backups. Filesystem removal is ordinary deletion, not secure erasure.

## Recovery

The agent removes payloads after it confirms test processes stopped, even if evidence upload fails. A protected journal/result buffer retries reporting. Locked files, unverifiable process termination or an orphan workspace hold the actor. Restart recovery retries safe removal/reporting without replaying execution.

Inspect the host, stop its remaining attempt processes and release file locks before recovery. Preserve journals and evidence. For an uncertain run or completed run with a removal hold, use **Execution History → run → Reconcile uncertain execution**, document the investigation and confirm process termination and downloaded-file removal. Reconciliation releases the server hold without changing the outcome or rerunning the test. Archive the exact local active journal only after investigation and recorded reconciliation, then restart the agent. Never clear state merely to make polling resume.

The approved request/approval snapshot does not change when packaging finishes; a separate immutable binding records the dispatch bundle. See [architecture](ARCHITECTURE.md#execution-and-file-delivery) and [agent contracts](API.md#agent-contract).

## Delivery mode and runtime updates

**Pinned checkout** remains a selectable mode for protected clean host catalogs. Linux manages its catalog from actor details; the Windows package installer can install a selected exact official commit. These requirements apply only to checkout actors.

For a runtime update, generate a fresh configuration-only ZIP for the same actor, verify its checksum and use the signed updater with the service stopped and no active/unreconciled work. It preserves the actor ID, credential and signing key. Select the intended delivery mode in the package and use the updater's matching `--enable-on-demand` option when selecting on-demand mode. The platform procedures are in [execution setup](EXECUTION_SETUP.md). Resolve queued work before changing mode because snapshots retain their original delivery binding.
