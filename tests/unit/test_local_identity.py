import ipaddress
import json
import ssl

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from apps.local_identity.network import validate_network
from apps.local_identity.realm import API, BROWSER, CODEX, MCP, ROLES, USER_ROLES, build_realm
from apps.local_identity.serve import SubnetOnly
from apps.local_identity.setup import (
    certificate_network_matches,
    complete_certificate,
    prepare,
    private_write,
)
from apps.local_identity.verify import LoginForm


def test_realm_has_separate_clients_and_no_password_or_service_grants():
    credentials = {
        "browser_secret": "test-browser",
        "mcp_secret": "test-mcp",
        "users": {name: "test-only" for name in USER_ROLES},
    }
    realm = build_realm(credentials)
    clients = {client["clientId"]: client for client in realm["clients"]}
    assert set(clients) == {API, BROWSER, CODEX, MCP}
    assert all(not client.get("directAccessGrantsEnabled", False) for client in clients.values())
    assert (
        not clients[MCP]["serviceAccountsEnabled"]
        and clients[MCP]["attributes"]["standard.token.exchange.enabled"] == "true"
    )
    assert (
        clients[BROWSER]["attributes"]["pkce.code.challenge.method"]
        == clients[CODEX]["attributes"]["pkce.code.challenge.method"]
        == "S256"
    )
    assert "http://127.0.0.1:1456/callback" in clients[CODEX]["redirectUris"]
    assert (
        realm["clientProfiles"]["profiles"][0]["executors"][0]["executor"]
        == "downscope-assertion-grant-enforcer"
    )
    assert set(USER_ROLES["atomic-operator"]) == {"viewer", "operator"}
    assert realm["accessTokenLifespan"] == 300
    assert realm["ssoSessionIdleTimeout"] == realm["ssoSessionMaxLifespan"] == 86400
    assert clients[BROWSER]["attributes"]["client.session.idle.timeout"] == "86400"
    assert clients[BROWSER]["attributes"]["client.session.max.lifespan"] == "86400"
    assert "privileged_approver" in USER_ROLES["atomic-approver"] and set(USER_ROLES["atomic-admin"]) == set(
        ROLES
    )


def test_local_secrets_and_strict_tls_certificates_are_private_and_idempotent(tmp_path):
    credentials, environment = prepare(tmp_path)
    again, _ = prepare(tmp_path)
    assert credentials == again
    assert environment["ATOMIC_MODE"] == "real" and environment["ATOMIC_DEV_AUTH"] == "false"
    assert environment["ATOMIC_APPROVAL_MODE"] == "catalog"
    assert environment["ATOMIC_BROWSER_SESSION_SECONDS"] == "86400"
    assert (tmp_path / "browser-session.key").stat().st_mode & 0o777 == 0o600
    saved_session_key = (tmp_path / "browser-session.key").read_bytes()
    prepare(tmp_path)
    assert (tmp_path / "browser-session.key").read_bytes() == saved_session_key
    assert environment["ATOMIC_DATABASE_URL"].endswith("atomic-real.db")
    assert (tmp_path / "credentials.json").stat().st_mode & 0o777 == 0o600
    assert all(
        credentials[key] not in (tmp_path / "authorization.yaml").read_text()
        for key in ["browser_secret", "mcp_secret"]
    )
    ca = x509.load_pem_x509_certificate((tmp_path / "tls/ca.pem").read_bytes())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    constraints = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert constraints.critical and x509.DNSName("localhost") in constraints.value.permitted_subtrees
    for service in ["control", "keycloak", "mcp"]:
        path = tmp_path / f"tls/{service}.pem"
        assert complete_certificate(path)
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        assert (
            cert.issuer == ca.subject
            and not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
        assert "localhost" in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        key = serialization.load_pem_private_key(
            (tmp_path / f"tls/{service}-key.pem").read_bytes(), password=None
        )
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()
        assert (tmp_path / f"tls/{service}-key.pem").stat().st_mode & 0o777 == 0o600
    context = ssl.create_default_context(cafile=str(tmp_path / "tls/ca-bundle.pem"))
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert json.loads((tmp_path / "credentials.json").read_text())["owner_id"] == credentials["owner_id"]


def test_login_form_parser_selects_only_the_identity_provider_login_form():
    form = LoginForm()
    form.feed(
        '<form id="unrelated" action="https://wrong.test"><input type="hidden" name="ignore" value="bad"></form><form id="kc-form-login" action="https://localhost:18443/login?a=1&amp;b=2"><input type="hidden" name="session" value="value"></form>'
    )
    assert form.action == "https://localhost:18443/login?a=1&b=2" and form.hidden == {"session": "value"}


def test_private_identity_material_cannot_overwrite_a_symlink(tmp_path):
    original = tmp_path / "original"
    original.write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(ValueError):
        private_write(link, b"overwrite")
    assert original.read_text() == "keep"


@pytest.mark.parametrize(
    "address, subnet",
    [
        ("8.8.8.8", "8.8.8.0/24"),
        ("192.168.1.2", "10.20.30.0/24"),
        ("10.20.30.0", "10.20.30.0/24"),
        ("10.20.30.255", "10.20.30.0/24"),
        ("10.20.30.10", "0.0.0.0/0"),
    ],
)
def test_lan_profile_refuses_public_wildcard_and_invalid_networks(address, subnet):
    with pytest.raises(ValueError):
        validate_network(address, subnet)


@pytest.mark.parametrize(
    "name",
    [
        "10.20.30.10",
        "localhost",
        "https://identity.test",
        "identity.test:18443",
        "identity.test/realm",
        "identity..test",
        "-identity.test",
        "identity.localhost",
    ],
)
def test_identity_hostname_rejects_ip_urls_and_invalid_dns(name):
    with pytest.raises(ValueError):
        validate_network("10.20.30.10", "10.20.30.0/24", name)
    with pytest.raises(ValueError):
        validate_network("10.20.30.10", "10.20.30.0/24", public_hostname=name)


def test_public_hostname_uses_existing_dns_ca_and_keeps_service_urls_stable(tmp_path):
    host = "control.example.test"
    network = validate_network("10.20.30.10", "10.20.30.0/24", host)
    private_write(tmp_path / "network.json", json.dumps(network).encode())
    credentials, original = prepare(tmp_path)
    ca = (tmp_path / "tls/ca.pem").read_bytes()
    identity_cert = (tmp_path / "tls/keycloak.pem").read_bytes()
    mcp_cert = (tmp_path / "tls/mcp.pem").read_bytes()
    network["public_hostname"] = host
    private_write(tmp_path / "network.json", json.dumps(network).encode())
    again, values = prepare(tmp_path)
    assert credentials == again
    assert values["ATOMIC_PUBLIC_URL"] == values["ATOMIC_API_URL"] == f"https://{host}:19443"
    assert values["ATOMIC_BIND_ADDRESS"] == "10.20.30.10"
    assert values["ATOMIC_OIDC_ISSUER"] == original["ATOMIC_OIDC_ISSUER"]
    assert values["ATOMIC_MCP_RESOURCE"] == original["ATOMIC_MCP_RESOURCE"]
    assert (tmp_path / "tls/ca.pem").read_bytes() == ca
    assert (tmp_path / "tls/keycloak.pem").read_bytes() == identity_cert
    assert (tmp_path / "tls/mcp.pem").read_bytes() == mcp_cert
    assert certificate_network_matches(tmp_path / "tls", "10.20.30.10", host, host)
    for service in ["control", "keycloak"]:
        cert = x509.load_pem_x509_certificate((tmp_path / f"tls/{service}.pem").read_bytes())
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert host in names.get_values_for_type(x509.DNSName)
        assert all(address.is_loopback for address in names.get_values_for_type(x509.IPAddress))
    network["address"] = "10.20.30.11"
    private_write(tmp_path / "network.json", json.dumps(network).encode())
    _, moved = prepare(tmp_path)
    assert moved["ATOMIC_PUBLIC_URL"] == values["ATOMIC_PUBLIC_URL"]
    assert moved["ATOMIC_OIDC_ISSUER"] == values["ATOMIC_OIDC_ISSUER"]
    from cryptography.x509.verification import PolicyBuilder, Store

    # A client retaining the original DNS-capable CA can still verify after the bind IP moves.
    verifier = (
        PolicyBuilder()
        .store(Store([x509.load_pem_x509_certificate(ca)]))
        .build_server_verifier(x509.DNSName(host))
    )
    verifier.verify(x509.load_pem_x509_certificate((tmp_path / "tls/control.pem").read_bytes()), [])


def test_dns_identity_preserves_agent_address_secrets_and_certificate_trust(tmp_path):
    credentials, _ = prepare(tmp_path)
    network = validate_network("10.20.30.10", "10.20.30.0/24", "Identity.Example.test")
    private_write(tmp_path / "network.json", json.dumps(network).encode())
    again, values = prepare(tmp_path)
    assert credentials == again
    assert values["ATOMIC_PUBLIC_URL"] == "https://10.20.30.10:19443"
    assert values["ATOMIC_BIND_ADDRESS"] == "10.20.30.10"
    issuer = "https://identity.example.test:18443/realms/atomic-control"
    assert values["ATOMIC_OIDC_ISSUER"] == issuer
    assert values["ATOMIC_OIDC_JWKS_URL"] == issuer + "/protocol/openid-connect/certs"
    assert values["ATOMIC_TOKEN_EXCHANGE_URL"] == issuer + "/protocol/openid-connect/token"
    override = json.loads((tmp_path / "compose.hostname.yaml").read_text())
    assert override["services"]["keycloak"]["extra_hosts"] == {"identity.example.test": "10.20.30.10"}
    assert certificate_network_matches(tmp_path / "tls", "10.20.30.10", "identity.example.test")
    assert not certificate_network_matches(tmp_path / "tls", "10.20.30.10", "other.example.test")
    for service in ["control", "mcp"]:
        cert = x509.load_pem_x509_certificate((tmp_path / f"tls/{service}.pem").read_bytes())
        assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        ) == ["localhost"]
    certificate = (tmp_path / "tls/keycloak.pem").read_bytes()
    prepare(tmp_path)
    assert (tmp_path / "tls/keycloak.pem").read_bytes() == certificate


def test_lan_configuration_preserves_secrets_and_limits_certificate_names(tmp_path):
    credentials, _ = prepare(tmp_path)
    private_write(
        tmp_path / "network.json", json.dumps(validate_network("10.20.30.10", "10.20.30.0/24")).encode()
    )
    again, values = prepare(tmp_path)
    assert again == credentials
    assert values["ATOMIC_BIND_ADDRESS"] == "10.20.30.10"
    assert values["ATOMIC_PUBLIC_URL"] == "https://10.20.30.10:19443"
    assert values["ATOMIC_OIDC_ISSUER"] == "https://10.20.30.10:18443/realms/atomic-control"
    assert values["ATOMIC_MCP_RESOURCE"] == MCP
    assert certificate_network_matches(tmp_path / "tls", "10.20.30.10")
    ca = x509.load_pem_x509_certificate((tmp_path / "tls/ca.pem").read_bytes())
    constraints = ca.extensions.get_extension_for_class(x509.NameConstraints).value
    assert x509.IPAddress(ipaddress.ip_network("10.20.30.10/32")) in constraints.permitted_subtrees
    assert x509.IPAddress(ipaddress.ip_network("10.20.30.0/24")) not in constraints.permitted_subtrees
    previous = (tmp_path / "tls/ca.pem").read_bytes()
    prepare(tmp_path)
    assert (tmp_path / "tls/ca.pem").read_bytes() == previous
    client = next(
        item
        for item in build_realm(credentials, control=values["ATOMIC_PUBLIC_URL"])["clients"]
        if item["clientId"] == BROWSER
    )
    assert client["redirectUris"] == ["https://10.20.30.10:19443/auth/callback"]


@pytest.mark.asyncio
async def test_lan_guard_uses_socket_peer_and_does_not_trust_forwarding_headers():
    from starlette.responses import PlainTextResponse

    app = SubnetOnly(PlainTextResponse("allowed"), subnet="10.20.30.0/24")
    for address, expected in [("10.20.30.42", 200), ("127.0.0.1", 200), ("10.0.0.4", 403)]:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(address, 1234)), base_url="https://control.test"
        ) as http:
            response = await http.get("/", headers={"X-Forwarded-For": "10.20.30.42"})
            assert response.status_code == expected
