# Implemented system specification

This document describes the implemented Atomic Control product. [Architecture](ARCHITECTURE.md) describes component interactions; `/openapi.json` on the running deployment defines request/response schemas.

## Supported workflows

| Area           | Implemented behavior                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Access         | OIDC sign-in; login-only unauthenticated UI; fixed 24-hour default sessions; username display and user-menu sign-out     |
| Catalog        | Official GitHub sync and YAML upload with preview/confirmation; exact commit/hash review, risk and allowed profiles      |
| Actors         | Windows/Linux registration, actor-specific agent ZIPs, enabled/disabled state, profile management and permanent deletion |
| Enrollment     | Single-use actor/hostname/platform-bound tokens; 60-minute default, tunable from 5 to 1,440 minutes in Settings          |
| Profiles       | Immutable local account/SID or UID bindings, automatic signed metadata synchronization and identity validation           |
| Execution      | One approved test/action/default-input snapshot, one attempt, signed grants, lease/fence, bounded result evidence        |
| Delivery       | Automatic central preparation and per-attempt download/removal; optional protected pinned-checkout mode                  |
| Queues         | Eligibility preview, selection/order of up to 500 tests on one actor/profile, FIFO, pause/resume/cancel-remaining        |
| Failures       | Continue after ordinary failures by default; safety/authorization/integrity and uncertain outcomes hold dispatch         |
| Cleanup        | Separate authorized action using the original retained bundle                                                            |
| Administration | Keycloak human-user creation, role changes, deletion, enrollment settings and audit                                      |
| MCP            | Caller-preserving discovery, test/check/cleanup requests, evidence and queue operations through REST                     |

Custom definitions can be submitted through REST and `atomic_add_custom_test` by operators. Submission is idempotent, append-only and unapproved; retained assets enter normal human review. Content revisions require no GitHub commit and execute through on-demand delivery. See [custom tests](CUSTOM_TESTS.md).

## Authorization contract

Default catalog approval is standing authorization for compatible operator requests. Optional per-run mode adds exact scoped grants and human approval, including a separate privileged approver for elevated execution. Imports and enrollment do not approve or execute tests. MCP cannot approve, reconcile or administer identities.

Requests accept test, actor and profile IDs, action, timeout and an optional reason. They accept no arbitrary command, account, executable path or input override. Platform, profile health/privilege, approved content and requester authorization are checked before dispatch and before execution readiness.

## Agent contract

Windows agents use LocalSystem transport and password-backed fixed scheduled tasks for verified standard-user/elevated tokens. Windows installation supplies Invoke-AtomicRedTeam and its YAML dependency; account creation, account passwords, task provisioning and batch-logon rights are local administrator responsibilities.

Linux agents use a root broker and fixed systemd runners under exact UID/GID profiles, with cgroup v2 process tracking. Both platforms use outbound verified HTTPS, rotating machine credentials, pinned signing keys, signed job/configuration grants and durable journals.

On-demand agents download only the current approved test and declared files. Execution and removal have distinct status/evidence. Automatic workspace removal does not perform test cleanup or secure erasure. Tests with external software requirements need separate provisioning.

## Durability and lifecycle

Approved snapshots, file plans, bundles and execution bindings are immutable. The YAML renderer omits empty optional inputs and re-approval replaces a stale cached representation with a new plan. Historical cleanup retains the original bundle.

One actor lease serializes execution. Stale fences cannot submit results. Central preparation and transfers can retry before execution; uncertain execution cannot replay. Reconciliation releases a hold only after administrator host investigation and preserves the original outcome.

Deleting actors or profiles preserves execution/audit history. Actor deletion releases the hostname for a new UUID/enrollment and does not uninstall host software. User deletion removes the provider account and blocks its subject while retaining audit attribution.

## Runtime and validation

The bundled management deployment supports macOS and Linux: Docker-hosted Keycloak/PostgreSQL, host-run API/dashboard/MCP, and a SQLite application database. Use canonical HTTPS hostnames, trusted certificates and one API worker. MCP is loopback-only in the bundled deployment.

Platform acceptance covers local service/task/systemd behavior, identities, containment, cancellation, cleanup and crash recovery. Isolated tests use temporary data and do not execute Atomic commands on enrolled hosts. See [validation](VALIDATION.md) and record the observed platform evidence.

Use the [installation guide](INSTALLATION_GUIDE.md), [user guide](SYSTEM_GUIDE.md), [execution setup](EXECUTION_SETUP.md) and [operations reference](OPERATIONS.md) for procedures.
