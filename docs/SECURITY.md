# Security model

Atomic Control requires OIDC, verified HTTPS and an RSA job-signing key. Catalog review authorizes compatible operator requests by default. Optional per-run mode adds exact scope grants and a separate human approval. Installation and startup grant no test approval and run no Atomic command.

## Authorization and content integrity

- Strict schemas accept registered IDs, approved actions/defaults and bounded timeouts. Jobs cannot specify arbitrary commands, accounts, executables or input overrides.
- Imports remain unapproved. Reviews bind exact definition hash/revision, GUID, platform, risk and profile type. Changed/revoked content cannot dispatch under an earlier review.
- File plans, source hashes, signed bundles, run snapshots and execution bindings are immutable. Re-approval can create a new rendered YAML plan while retaining historical bytes.
- On-demand download and execution grants are distinct. Actor readiness rechecks current authorization before execution. Grants bind audience, attempt, fence, snapshot and deadlines.
- Request, queue, claim and readiness checks enforce current actor/profile enablement, health, platform, privilege and approval. In per-run mode exact subject grants and separate approvals also apply; privileged requesters cannot self-approve elevated work.
- One durable actor lease serializes attempts. Stale fences cannot report; unknown execution never automatically requeues. Reconciliation is explicit and audited.
- Local runners verify actual token/UID evidence before launching approved commands. Server validation requires matching identity and successful exit evidence for success.

Catalog imports use the fixed official GitHub source, exact commits and bounded archive processing without payload execution. YAML parsing rejects duplicate keys, anchors, aliases and executable tags. Custom supporting files are bounded and explicitly approved. Custom submissions cannot overwrite a GUID; file paths/hashes are validated and retained without executing content. Cross-source GUID replacement requires confirmation. React renders catalog text without raw HTML evaluation.

Prerequisite checks execute reviewed commands. Windows installation supplies the execution framework, but test-specific dependency installation is not automatic. Test cleanup is separately authorized; downloaded-file deletion does not reverse test effects.

## Human and MCP authentication

Browser sign-in uses code/PKCE, state and nonce. Access/refresh tokens stay encrypted server-side; opaque session identifiers are hashed in storage. Cookies are Secure, HttpOnly and SameSite=Strict. Sessions default to a fixed 24 hours; refresh/activity do not extend that deadline. Logout durably removes the session and attempts provider revocation. Preserve the session encryption key with backups.

The dashboard mounts only after authorization and clears state on authorization loss. Every API endpoint independently checks identity/roles. Mutation origins must match the configured origin. One API worker is required for process-local pending login/permission previews. Production ignores identity-selection headers and stores no credentials in localStorage.

MCP authenticates the caller and uses constrained token exchange for API audience while preserving subject/scopes. API rights are reduced to read/request/cleanup regardless of claimed administrator roles. MCP cannot approve/reconcile tests, replace catalog GUIDs or manage users/actors. Operator callers with `atomic:request` may append unapproved custom YAML through the bounded, idempotent submission endpoint; human review is still required. Token exchange fails closed without provider support.

## Agent credentials and configuration

Enrollment tokens are single-use and actor/hostname/platform-bound. Their default lifetime is 60 minutes, with persisted administrator limits of 5–1,440 minutes for future issuance. Transport credentials are unique, expiring, hashed server-side and rotated. Windows uses DPAPI plus protected ACLs; Linux uses root-only files. TLS trust is separate from enrollment and signed-job verification.

Agents pin the public signing key. Job/configuration grants use RS256 with explicit purpose/issuer/audience checks. Five-second `iat` backdating tolerates small clock differences without extending expiration, approval or lease limits.

Profile synchronization accepts only allowlisted actor/platform metadata, never commands, URLs, paths or passwords. Generations and canonical hashes prevent replay/conflict. Applying changes waits for an idle agent and identity probes. Configuration errors block new dispatch. Account creation, batch-logon rights and password-backed task provisioning remain local administrator work.

Runtime updates validate the signed package against the already installed key, retain actor/API/key bindings and credentials, and refuse active/uncertain work. Protect the interpreter, configuration, framework/dependencies and wrappers from execution-profile writes. A framework manifest hash is checked before import; setup verifies/protects the complete pinned source tree.

## Deletion and user administration

Permanent actor deletion requires a human administrator and exact-hostname confirmation. Active leases, applying changes and unresolved work block it. It removes registration/profiles/credentials/enrollment and cancels waiting work while retaining original IDs, snapshots and evidence. Hostname reuse creates a new identity. Profile deletion similarly removes authorization and synchronizes local metadata/task removal while retaining history and local accounts/files. Host uninstall is separate.

Keycloak user management uses a separate protected server-side client. Temporary passwords are never persisted by Atomic Control or returned in responses. Users are enabled only after exact application-role assignment succeeds. Human administrators can change supported direct application roles or delete accounts; self role-edit/deletion and service-account deletion are refused. Password resets remain in the provider.

Role edits/deletion place the target on a durable access hold and remove local sessions before provider mutation. Stale versions are rejected; incomplete changes remain held until reconciled. Deleted subjects stay blocked even if an old signed access token has not expired. History retains immutable subject attribution. No previously authorized run is implicitly cancelled by user deletion.

## Operational boundaries

Deploy as one trusted workspace. Viewers can see catalog, actors and evidence; per-result tenancy isolation is not implemented. Host/database administrators are trusted, and writable output is host reporting rather than tamper-proof attestation. A hostile root/administrator can defeat local controls. Windows Job Objects and Linux cgroups provide lifecycle tracking, not a sandbox against a hostile privileged test.

Exit codes/logs establish execution evidence, not security-product detection or complete host cleanup. Output redaction is pattern-based and cannot recognize every secret. Restrict evidence access and retention and approve commands with their output implications in mind.

Use trusted HTTPS, network filtering, endpoint-appropriate body limits and auth rate limits. Keep private keys, environment files and identity volumes protected. Avoid callback query strings in logs. Audit lifecycle/authorization changes and use an external protected sink if stronger retention is required. Keep immutable bundles for historical cleanup and plan storage accordingly. Validate actual platform behavior using [the acceptance procedure](VALIDATION.md).
