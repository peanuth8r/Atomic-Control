# Execution identities

An actor is a registered Windows or Linux execution host. A profile binds an immutable UUID to an existing local account, exact SID/UID and privilege on that actor. Requests select a profile ID; they cannot substitute account names, passwords or task actions.

| Platform/profile      | Required identity                                                                           | Local dispatch                      |
| --------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------- |
| Windows standard-user | Exact SID, no Administrators membership including deny-only, not elevated, medium integrity | Password-backed Task Scheduler task |
| Windows local-admin   | Exact SID, enabled administrator token, elevated, high integrity                            | Password-backed Task Scheduler task |
| Linux standard-user   | Exact nonzero UID, no root group/capabilities, NoNewPrivileges                              | Fixed systemd runner                |
| Linux local-admin     | Root UID/GID 0                                                                              | Fixed systemd runner                |

The profile key `local-admin` represents the elevated identity on either platform. Domain, interactive and S4U profiles are unsupported. Register only identities required by the host's intended tests.

## Windows evidence and provisioning

Python reads the actual process token: SID/account, administrator groups, elevation, integrity, authentication session and PID. A filtered administrator is not a standard user; membership alone does not establish an elevated token. LocalSystem is the service identity and is not accepted as an administrator execution profile. The PowerShell child rechecks identity before importing the pinned framework.

Create accounts locally. Provision fixed tasks using the bundled helper and the service's protected all-users Python. Enter account passwords only in the local Windows credential prompt. Passwords never enter JSON, REST, MCP, browser storage or logs.

Each account needs **Log on as a batch job** (`SeBatchLogonRight`). An applicable **Deny log on as a batch job** policy overrides it. Configure local/domain policy; the helper does not grant these rights. Task Scheduler events 101/104 with `2147943785` (`0x80070569`) identify a logon-right failure. A `0x41303` result means never run, not the probe's exit status. See [profile troubleshooting](WINDOWS_PROFILE_REPAIR.md).

## Linux evidence

The runner reads the account database and `/proc/self/status`: real/effective/saved/filesystem IDs, groups, capability masks, NoNewPrivs and PID. Root identity requires UID/GID 0; standard identity must remain non-root without root groups or capabilities. API result validation checks Linux evidence separately from Windows tokens.

## Synchronization and health

Administrators register/delete profile definitions in actor details. Idle agents fetch signed actor/platform-bound generations and apply metadata, then run identity-only probes. Windows task/password provisioning remains local. Use **Retry validation** after correcting host state rather than setting `validated=true` manually.

Profile definition, agent transport identity, human SSO identity and profile health are separate. Only enabled healthy compatible profiles can execute. Active/uncertain work defers metadata changes. Deletion preserves execution history and local accounts/files; Windows removes verified fixed tasks automatically. See [execution setup](EXECUTION_SETUP.md).
