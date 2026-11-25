# Documentation

These documents describe the implemented product and its supported operations.

| Document                                                    | Purpose                                                                |
| ----------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Project overview](../README.md)                            | Features, screenshots and high-level architecture                      |
| [Installation guide](INSTALLATION_GUIDE.md)                 | Install the management services on macOS or Linux                      |
| [User guide](SYSTEM_GUIDE.md)                               | Catalog, actors, profiles, runs, queues, users and settings            |
| [Architecture](ARCHITECTURE.md)                             | Components, trust boundaries, persistence and execution flow           |
| [System specification](SPECIFICATION.md)                    | Implemented product behavior and contracts                             |
| [Deployment](DEPLOYMENT.md)                                 | Deployment topology, service responsibilities and network requirements |
| [Operations](OPERATIONS.md)                                 | Start/stop, service managers, backups, upgrades and certificates       |
| [Keycloak](KEYCLOAK.md)                                     | Identity configuration, roles, HTTPS and management client             |
| [Security](SECURITY.md)                                     | Enforced checks and operational trust limits                           |
| [Catalog imports](CATALOG_IMPORTS.md)                       | GitHub/YAML import and approval                                        |
| [Custom tests](CUSTOM_TESTS.md)                             | Add unapproved custom YAML and supporting files through REST or MCP    |
| [Execution setup](EXECUTION_SETUP.md)                       | Profiles, runtime updates, delivery modes and eligibility              |
| [Execution identities](EXECUTION_IDENTITIES.md)             | Windows token and Linux UID/GID requirements                           |
| [On-demand delivery](ON_DEMAND_TEST_DELIVERY.md)            | Automatic preparation, downloads, removal and recovery                 |
| [Windows packages](AGENT_PACKAGES.md)                       | Generate and install Windows agent packages                            |
| [Windows agent](AGENT.md)                                   | Broker, fixed tasks, diagnostics and recovery                          |
| [Windows prerequisites](WINDOWS_EXECUTION_PREREQUISITES.md) | Framework installation and execution troubleshooting                   |
| [Windows profile repair](WINDOWS_PROFILE_REPAIR.md)         | Interpreter/task-path and batch-logon troubleshooting                  |
| [Linux agent](LINUX_AGENT.md)                               | Install, validate, update and recover Linux agents                     |
| [REST API](API.md)                                          | Current endpoint groups and lifecycle contracts                        |
| [MCP](MCP.md)                                               | Tool inventory, scopes and caller-preserving delegation                |
| [Codex plugin](CODEX_PLUGIN.md)                             | Configure the plugin or a standalone MCP connection                    |
| [Validation](VALIDATION.md)                                 | Automated checks and platform acceptance                               |
