# Validation

Automated checks use isolated databases, transport/native-API stubs and synthetic evidence. They do not start an enrolled agent or execute Atomic tests. Platform acceptance must establish actual service, account/token, containment, cleanup and recovery behavior on the intended hosts.

## Automated checks

```sh
.venv/bin/ruff check apps scripts tests
.venv/bin/ruff format --check apps scripts tests
.venv/bin/mypy apps scripts
.venv/bin/pytest tests/unit tests/integration -q
pnpm --dir apps/frontend build
pnpm --dir apps/frontend test
```

PowerShell orchestration tests run fixture modules and mocked enrollment/native actions, never Atomic commands. They exercise installer ordering/failure, pinned-source reuse and Windows platform-variable compatibility. The Python suite covers authorization, catalog import/review, immutable file plans/bindings, queues, preparation, grants, identities, credentials, synchronization, deletion and uncertain-state recovery.

For browser regressions, start `.venv/bin/python -m tests.support.browser_stack`, then run Playwright using `ATOMIC_DASHBOARD_TEST_URL=http://127.0.0.1:15173`. Its authentication overrides and synthetic host results stay under `tests/`. Opt-in live Keycloak checks verify identity/read access with application writes blocked. Record the observed results for the deployment.

## Management-host acceptance

- Verify trusted HTTPS and matching DNS/certificate names from server, browser and actors. Check health/readiness and unauthenticated API rejection.
- Verify login-only UI before authorization, each application role, fixed session deadline, token refresh, username display and sign-out.
- Verify user creation, supported role edits/deletion, stale/self-action rejection and access holds using deliberate administrator test accounts.
- Verify MCP protected-resource discovery, exact callback/PKCE, caller-preserving token exchange, 14 submission/execution/queue tools, scope enforcement and refusal of approval/administration calls.
- Exercise consistent application/identity backup and restore while preserving keys, immutable history and user-access revocations.

## Windows host acceptance

1. Generate/verify an enrollment ZIP and install with protected all-users Python and Administrator Windows PowerShell 5.1. Confirm HTTPS/CA preflight, automatic pinned framework/YAML setup before enrollment, protected state and requested service-start behavior.
2. Provision only intended existing local accounts, batch-logon rights and fixed password-backed tasks. Standard accounts must not belong to Administrators; elevated accounts must produce high-integrity administrator tokens.
3. Register profiles through the dashboard, verify automatic metadata synchronization and token-only probes, then inspect actual SID/groups/elevation/integrity independently. Reject mismatched identities, task actions, interpreter paths and writable runtime/configuration.
4. Approve an explicitly authorized low-risk test with on-demand delivery. Confirm central preparation, download/signature/hash checks and separate execution readiness. Verify the selected GUID/defaults and that no whole catalog is installed.
5. Run only the intended authorized actions and inspect exit/evidence and the Windows Job Object/process state. Verify downloaded-file removal and separate test cleanup. Interactive-desktop tests are outside the supported batch execution model.
6. Exercise cancellation, deadlines, output caps, disconnection, service/machine restart and lost acknowledgements. Confirm no execution replay, no surviving contained processes after verified stop, durable uncertainty holds and explicit reconciliation.

## Linux host acceptance

1. Install a named actor on systemd 245+/cgroup v2 with Python 3.12+. Confirm protected paths/credentials and stopped/disabled service until explicitly enabled.
2. Verify automatic signed profile synchronization and actual UID/GID/group/capability/NoNewPrivs evidence for each intended identity. Reject nonmatching identities and Windows-shaped evidence.
3. Explicitly authorize a low-risk bash/sh test/check/cleanup through normal catalog or per-run approval. Confirm per-attempt bundle delivery, exact defaults, exit evidence and removal.
4. Exercise cancellation, output bounds, timeouts, detached descendants, transport failure and broker restart. Verify complete cgroup stop, durable journals/leases, no replay and administrator reconciliation.
5. Verify runtime updates preserve enrollment and refuse uncertain work. Verify profile removal deletes metadata while retaining local accounts and history.

## Cross-platform invariants

- A matching-platform list is not authorization: current actor/profile health, exact content approval and requester rights must pass at dispatch/readiness.
- Default catalog mode queues compatible approved requests. Separately test optional per-run scope/approval and elevated self-approval rejection when that mode is enabled.
- One actor attempt may hold its lease. Reject stale fences, wrong audiences, changed snapshots, expired tokens and conflicting results.
- Queues preserve order across restarts; ordinary failure follows Continue/Pause while uncertain/integrity/authorization failures hold dispatch.
- Re-approval refreshes stale rendered YAML without rewriting historical plans/bindings. Historical cleanup uses its original bundle.
- Actor/profile deletion blocks on active/uncertain work, preserves evidence and gives replacements new UUIDs. Hostname reuse cannot inherit credentials or jobs.

Record native platform evidence for the deployment. Passing isolated tests does not prove security-tool detection, tamper-proof evidence, complete test cleanup or behavior on a different operating-system version.
