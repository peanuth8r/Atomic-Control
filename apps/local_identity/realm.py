"""Keycloak realm with separate human and MCP clients and explicit claim/audience mappers."""

ROLES = ["viewer", "operator", "approver", "privileged_approver", "administrator"]
API = "atomic-control"
BROWSER = "atomic-control-browser"
MCP = "https://localhost:19444/mcp"
CODEX = "atomic-control-codex"
REALM = "atomic-control"
CONTROL = "https://localhost:19443"
SESSION_SECONDS = 86400
ISSUER = "https://localhost:18443/realms/" + REALM
USER_ROLES = {
    "atomic-viewer": ["viewer"],
    "atomic-operator": ["viewer", "operator"],
    "atomic-approver": ["viewer", "approver", "privileged_approver"],
    "atomic-admin": ROLES,
}


def mapper(name, kind, config):
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": kind,
        "consentRequired": False,
        "config": config,
    }


def audience(value):
    return mapper(
        "audience-" + value,
        "oidc-audience-mapper",
        {"included.client.audience": value, "access.token.claim": "true", "id.token.claim": "false"},
    )


def app_roles():
    return mapper(
        "atomic-roles",
        "oidc-usermodel-client-role-mapper",
        {
            "usermodel.clientRoleMapping.clientId": API,
            "claim.name": "roles",
            "jsonType.label": "String",
            "multivalued": "true",
            "access.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false",
        },
    )


def scope(name, mappers=None, visible=True):
    return {
        "name": name,
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": str(visible).lower(), "display.on.consent.screen": "false"},
        "protocolMappers": mappers or [],
    }


def build_realm(credentials: dict, control: str = CONTROL):
    basic = scope(
        "basic",
        [
            mapper(
                "sub", "oidc-sub-mapper", {"access.token.claim": "true", "introspection.token.claim": "true"}
            )
        ],
        False,
    )
    profile = scope(
        "profile",
        [
            mapper(
                "username",
                "oidc-usermodel-property-mapper",
                {
                    "user.attribute": "username",
                    "claim.name": "preferred_username",
                    "jsonType.label": "String",
                    "access.token.claim": "true",
                    "id.token.claim": "true",
                },
            )
        ],
    )
    human_claims = scope("atomic-human-claims", [app_roles(), audience(API)], False)
    mcp_claims = scope("atomic-mcp-claims", [app_roles(), audience(MCP)], False)
    exchange_claims = scope("atomic-exchange-claims", [app_roles(), audience(API)], False)
    atomic_scopes = [scope(name) for name in ["atomic:read", "atomic:request", "atomic:cleanup"]]
    clients = [
        {
            "clientId": API,
            "name": "Atomic Control API",
            "protocol": "openid-connect",
            "bearerOnly": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
        },
        {
            "clientId": BROWSER,
            "name": "Atomic Control browser",
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": credentials["browser_secret"],
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": [control + "/auth/callback"],
            "webOrigins": [control],
            "defaultClientScopes": ["basic", "profile", "atomic-human-claims"],
            "optionalClientScopes": [],
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "client.session.idle.timeout": str(SESSION_SECONDS),
                "client.session.max.lifespan": str(SESSION_SECONDS),
            },
        },
        {
            "clientId": MCP,
            "name": "Atomic Control MCP exchange",
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": credentials["mcp_secret"],
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "defaultClientScopes": ["basic", "atomic-exchange-claims"],
            "optionalClientScopes": ["atomic:read", "atomic:request", "atomic:cleanup"],
            "attributes": {"standard.token.exchange.enabled": "true"},
        },
        {
            "clientId": CODEX,
            "name": "Atomic Control local MCP client",
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": [
                "http://127.0.0.1:1455/oauth/callback",
                "http://127.0.0.1:1456/callback",
            ],
            "defaultClientScopes": ["basic", "atomic-mcp-claims"],
            "optionalClientScopes": ["atomic:read", "atomic:request", "atomic:cleanup"],
            "attributes": {"pkce.code.challenge.method": "S256"},
        },
    ]
    return {
        "realm": REALM,
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "loginWithEmailAllowed": False,
        "resetPasswordAllowed": False,
        "bruteForceProtected": True,
        "defaultSignatureAlgorithm": "RS256",
        "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": SESSION_SECONDS,
        "ssoSessionMaxLifespan": SESSION_SECONDS,
        "roles": {"client": {API: [{"name": role} for role in ROLES]}},
        "clientScopes": [basic, profile, human_claims, mcp_claims, exchange_claims, *atomic_scopes],
        "defaultDefaultClientScopes": [],
        "defaultOptionalClientScopes": [],
        "clients": clients,
        "users": [
            {
                "username": name,
                "enabled": True,
                "emailVerified": True,
                "firstName": "Atomic",
                "lastName": name.removeprefix("atomic-"),
                "email": name + "@localhost.invalid",
                "credentials": [
                    {"type": "password", "value": credentials["users"][name], "temporary": False}
                ],
                "clientRoles": {API: roles},
                "requiredActions": [],
            }
            for name, roles in USER_ROLES.items()
        ],
        "clientProfiles": {
            "profiles": [
                {
                    "name": "atomic-exchange-downscope",
                    "description": "Never grant MCP scopes absent from the incoming caller token",
                    "executors": [{"executor": "downscope-assertion-grant-enforcer", "configuration": {}}],
                }
            ]
        },
        "clientPolicies": {
            "policies": [
                {
                    "name": "atomic-exchange-downscope",
                    "enabled": True,
                    "conditions": [
                        {"condition": "client-access-type", "configuration": {"type": ["confidential"]}}
                    ],
                    "profiles": ["atomic-exchange-downscope"],
                }
            ]
        },
    }
