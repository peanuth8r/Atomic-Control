"""Generate private local TLS/secrets and provision an owned Keycloak realm over verified HTTPS."""

import datetime as dt
import ipaddress
import json
import os
import secrets
import ssl
import stat
import subprocess
import time
from pathlib import Path

import certifi
import httpx
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .network import load_network, public_urls, validate_network
from .realm import API, BROWSER, MCP, REALM, SESSION_SECONDS, USER_ROLES, build_realm

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "artifacts/keycloak"
KEYCLOAK = "https://localhost:18443"
COMPOSE = ROOT / "deploy/keycloak/compose.yaml"


def private_write(path: Path, value: bytes):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing a symlink for local identity material")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(value)


def key_bytes(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def rsa_key(path):
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Local identity keys must use RSA")
        return key
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def complete_certificate(path):
    if not path.is_file():
        return False
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    try:
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            cert.extensions.get_extension_for_class(x509.NameConstraints)
        return True
    except x509.ExtensionNotFound:
        return False


def ca_network_matches(tls, address, identity_hostname=None, public_hostname=None):
    if not complete_certificate(tls / "ca.pem"):
        return False
    ca = x509.load_pem_x509_certificate((tls / "ca.pem").read_bytes())
    constraints = ca.extensions.get_extension_for_class(x509.NameConstraints).value
    expected = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_network("127.0.0.0/8")),
        x509.IPAddress(ipaddress.ip_network("::1/128")),
    ]
    if address != "localhost":
        expected.append(x509.IPAddress(ipaddress.ip_network(address + "/32")))
    for hostname in {identity_hostname, public_hostname} - {None}:
        expected.append(x509.DNSName(hostname))
    if set(constraints.permitted_subtrees or []) != set(expected):
        return False
    return True


def service_certificate_matches(tls, service, address, hostname=None):
    path = tls / f"{service}.pem"
    if not complete_certificate(path) or not (tls / f"{service}-key.pem").is_file():
        return False
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if hostname and hostname not in names.get_values_for_type(x509.DNSName):
        return False
    addresses = names.get_values_for_type(x509.IPAddress)
    if (hostname or service == "mcp") and any(not value.is_loopback for value in addresses):
        return False
    if (
        not hostname
        and service != "mcp"
        and address != "localhost"
        and ipaddress.ip_address(address) not in names.get_values_for_type(x509.IPAddress)
    ):
        return False
    key = rsa_key(tls / f"{service}-key.pem")
    public = cert.public_key()
    if (
        not isinstance(public, rsa.RSAPublicKey)
        or public.public_numbers() != key.public_key().public_numbers()
    ):
        return False
    try:
        cert.verify_directly_issued_by(x509.load_pem_x509_certificate((tls / "ca.pem").read_bytes()))
    except (ValueError, TypeError):
        return False
    return True


def certificate_network_matches(tls, address, identity_hostname=None, public_hostname=None):
    return ca_network_matches(tls, address, identity_hostname, public_hostname) and all(
        service_certificate_matches(tls, service, address, hostname)
        for service, hostname in [
            ("control", public_hostname),
            ("keycloak", identity_hostname),
            ("mcp", None),
        ]
    )


def prepare(runtime: Path = RUNTIME):
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime.chmod(0o700)
    network = load_network(runtime)
    control, keycloak = public_urls(network)
    issuer = keycloak + "/realms/" + REALM
    secrets_file = runtime / "credentials.json"
    if secrets_file.exists():
        if secrets_file.stat().st_mode & 0o077:
            raise ValueError("Credentials file permissions must be 0600")
        credentials = json.loads(secrets_file.read_text())
    else:
        credentials = {
            "bootstrap_password": secrets.token_urlsafe(36),
            "database_password": secrets.token_urlsafe(36),
            "browser_secret": secrets.token_urlsafe(36),
            "mcp_secret": secrets.token_urlsafe(36),
            "owner_id": secrets.token_hex(24),
            "users": {name: secrets.token_urlsafe(24) for name in USER_ROLES},
        }
        private_write(secrets_file, json.dumps(credentials, indent=2).encode())
    if "user_management_secret" not in credentials:
        credentials["user_management_secret"] = secrets.token_urlsafe(36)
        private_write(secrets_file, json.dumps(credentials, indent=2).encode())
    tls = runtime / "tls"
    tls.mkdir(mode=0o700, exist_ok=True)
    if not certificate_network_matches(
        tls, network["address"], network.get("identity_hostname"), network.get("public_hostname")
    ):
        ca_key = rsa_key(tls / "ca-key.pem")
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Atomic Control Local Identity CA")])
        now = dt.datetime.now(dt.UTC)
        permitted = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_network("127.0.0.0/8")),
            x509.IPAddress(ipaddress.ip_network("::1/128")),
        ]
        names = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]
        if network["address"] != "localhost":
            permitted.append(x509.IPAddress(ipaddress.ip_network(network["address"] + "/32")))
            names.append(x509.IPAddress(ipaddress.ip_address(network["address"])))
        for hostname in {network.get("identity_hostname"), network.get("public_hostname")} - {None}:
            permitted.append(x509.DNSName(hostname))
        reuse_ca = ca_network_matches(
            tls, network["address"], network.get("identity_hostname"), network.get("public_hostname")
        )
        if reuse_ca:
            ca = x509.load_pem_x509_certificate((tls / "ca.pem").read_bytes())
            public = ca.public_key()
            if (
                not isinstance(public, rsa.RSAPublicKey)
                or public.public_numbers() != ca_key.public_key().public_numbers()
            ):
                raise ValueError("Existing CA certificate and signing key do not match")
        else:
            ca = (
                x509.CertificateBuilder()
                .subject_name(ca_name)
                .issuer_name(ca_name)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.NameConstraints(
                        permitted_subtrees=permitted,
                        excluded_subtrees=None,
                    ),
                    critical=True,
                )
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(ca_key, hashes.SHA256())
            )
        private_write(tls / "ca-key.pem", key_bytes(ca_key))
        private_write(tls / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
        for service in ["keycloak", "control", "mcp"]:
            service_names = list(names)
            hostname = network.get(
                {"keycloak": "identity_hostname", "control": "public_hostname"}.get(service, "")
            )
            if reuse_ca and service_certificate_matches(tls, service, network["address"], hostname):
                continue
            if hostname:
                service_names.append(x509.DNSName(hostname))
            if hostname or service == "mcp":
                service_names = [
                    name
                    for name in service_names
                    if not isinstance(name, x509.IPAddress) or name.value.is_loopback
                ]
            key = rsa_key(tls / f"{service}-key.pem")
            cert = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Atomic Control " + service)])
                )
                .issuer_name(ca.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectAlternativeName(service_names),
                    critical=False,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
                )
                .sign(ca_key, hashes.SHA256())
            )
            private_write(tls / f"{service}-key.pem", key_bytes(key))
            private_write(tls / f"{service}.pem", cert.public_bytes(serialization.Encoding.PEM))
    for name in ["keycloak", "control", "mcp"]:
        if not (tls / f"{name}.pem").is_file() or not (tls / f"{name}-key.pem").is_file():
            raise ValueError("Incomplete existing TLS material; recover it before continuing")
    private_write(
        tls / "ca-bundle.pem", Path(certifi.where()).read_bytes() + b"\n" + (tls / "ca.pem").read_bytes()
    )
    private_write(runtime / "atomic-control-ca.crt", (tls / "ca.pem").read_bytes())
    if not (runtime / "job-signing-private.pem").exists():
        private_write(
            runtime / "job-signing-private.pem",
            key_bytes(rsa.generate_private_key(public_exponent=65537, key_size=3072)),
        )
    private_write(
        runtime / "compose.env",
        (
            f'KEYCLOAK_RUNTIME="{runtime}"\nKEYCLOAK_DB_PASSWORD={credentials["database_password"]}\nKEYCLOAK_BOOTSTRAP_PASSWORD={credentials["bootstrap_password"]}\nKEYCLOAK_PUBLIC_URL={keycloak}\nKEYCLOAK_LAN_ADDRESS={network["address"]}\n'
        ).encode(),
    )
    hostname_override = runtime / "compose.hostname.yaml"
    if network.get("identity_hostname"):
        private_write(
            hostname_override,
            json.dumps(
                {
                    "services": {
                        "keycloak": {"extra_hosts": {network["identity_hostname"]: network["address"]}}
                    }
                }
            ).encode(),
        )
    else:
        hostname_override.unlink(missing_ok=True)
    session_key = runtime / "browser-session.key"
    if not session_key.exists():
        private_write(session_key, Fernet.generate_key())
    info = session_key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("The browser session key must remain owner-only")
    Fernet(session_key.read_bytes().strip())
    values = {
        "ATOMIC_BROWSER_SESSION_SECONDS": str(SESSION_SECONDS),
        "ATOMIC_BROWSER_SESSION_KEY_FILE": str(session_key),
        "ATOMIC_USER_MANAGEMENT_PROVIDER": "keycloak",
        "ATOMIC_KEYCLOAK_MANAGEMENT_CLIENT_ID": "atomic-control-user-management",
        "ATOMIC_KEYCLOAK_MANAGEMENT_CLIENT_SECRET": credentials["user_management_secret"],
        "ATOMIC_MODE": "real",
        "ATOMIC_DEV_AUTH": "false",
        "ATOMIC_APPROVAL_MODE": "catalog",
        "ATOMIC_DATABASE_URL": "sqlite:///" + str(runtime / "atomic-real.db"),
        "ATOMIC_PUBLIC_URL": control,
        "ATOMIC_BIND_ADDRESS": "127.0.0.1" if network["address"] == "localhost" else network["address"],
        "ATOMIC_ALLOWED_SUBNET": network["subnet"],
        "ATOMIC_OIDC_ISSUER": issuer,
        "ATOMIC_OIDC_JWKS_URL": issuer + "/protocol/openid-connect/certs",
        "ATOMIC_OIDC_AUDIENCE": API,
        "ATOMIC_OIDC_CLIENT_ID": BROWSER,
        "ATOMIC_OIDC_CLIENT_SECRET": credentials["browser_secret"],
        "ATOMIC_SIGNING_KEY_FILE": str(runtime / "job-signing-private.pem"),
        "ATOMIC_AGENT_PUBLIC_CA_FILE": str(runtime / "atomic-control-ca.crt"),
        "ATOMIC_POLICY_FILE": str(runtime / "authorization.yaml"),
        "ATOMIC_API_URL": control,
        "ATOMIC_MCP_RESOURCE": MCP,
        "ATOMIC_TOKEN_EXCHANGE_URL": issuer + "/protocol/openid-connect/token",
        "ATOMIC_MCP_CLIENT_ID": MCP,
        "ATOMIC_MCP_CLIENT_SECRET": credentials["mcp_secret"],
        "ATOMIC_MCP_CLIENT_IDS": MCP,
        "SSL_CERT_FILE": str(tls / "ca-bundle.pem"),
        "ATOMIC_GITHUB_TOKEN": "",
    }
    private_write(
        runtime / "application.env",
        ("\n".join(k + "=" + json.dumps(v) for k, v in values.items()) + "\n").encode(),
    )
    if not (runtime / "authorization.yaml").exists():
        private_write(
            runtime / "authorization.yaml",
            b"# Add exact subject/actor/profile/test grants after enrolling your real host.\nsubjects: {}\n",
        )
    return credentials, values


def compose(*arguments, runtime: Path = RUNTIME):
    files = ["-f", str(COMPOSE)]
    if load_network(runtime)["address"] != "localhost":
        files += ["-f", str(COMPOSE.with_name("compose.lan.yaml"))]
    if load_network(runtime).get("identity_hostname"):
        files += ["-f", str(runtime / "compose.hostname.yaml")]
    subprocess.run(
        ["docker", "compose", "--env-file", str(runtime / "compose.env"), *files, *arguments],
        check=True,
        cwd=ROOT,
    )


def provision(runtime: Path = RUNTIME):
    credentials, values = prepare(runtime)
    control = values["ATOMIC_PUBLIC_URL"]
    context = ssl.create_default_context(cafile=str(runtime / "tls/ca-bundle.pem"))
    with httpx.Client(verify=context, timeout=15, trust_env=False, follow_redirects=False) as http:
        deadline = time.monotonic() + 180
        while True:
            try:
                ready = http.get(KEYCLOAK + "/realms/master/.well-known/openid-configuration")
                if ready.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("Keycloak did not become HTTPS-ready; inspect docker compose logs")
            time.sleep(1)
        response = http.post(
            KEYCLOAK + "/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "atomic-bootstrap",
                "password": credentials["bootstrap_password"],
            },
        )
        response.raise_for_status()
        http.headers["Authorization"] = "Bearer " + response.json()["access_token"]
        path = KEYCLOAK + "/admin/realms/" + REALM
        existing = http.get(path)
        if existing.status_code == 404:
            payload = build_realm(credentials, control=control)
            payload["attributes"] = {"atomic-control-owner": credentials["owner_id"]}
            created = http.post(KEYCLOAK + "/admin/realms", json=payload)
            if created.status_code != 201:
                raise RuntimeError(
                    f"Keycloak realm creation refused ({created.status_code}): {created.text[:500]}"
                )
        else:
            existing.raise_for_status()
            if existing.json().get("attributes", {}).get("atomic-control-owner") != credentials["owner_id"]:
                raise ValueError("An unrelated realm already uses this name; it will not be overwritten")
        browser = http.get(path + "/clients", params={"clientId": BROWSER}).raise_for_status().json()
        if len(browser) != 1:
            raise ValueError("Expected exactly one owned browser client")
        http.put(
            path, json={"ssoSessionIdleTimeout": SESSION_SECONDS, "ssoSessionMaxLifespan": SESSION_SECONDS}
        ).raise_for_status()
        browser_client = http.get(path + "/clients/" + browser[0]["id"]).raise_for_status().json()
        attributes = {
            **browser_client.get("attributes", {}),
            "pkce.code.challenge.method": "S256",
            "client.session.idle.timeout": str(SESSION_SECONDS),
            "client.session.max.lifespan": str(SESSION_SECONDS),
        }
        # Preserve accounts, roles, client secrets and unrelated client attributes.
        http.put(
            path + "/clients/" + browser[0]["id"],
            json={
                "redirectUris": [control + "/auth/callback"],
                "webOrigins": [control],
                "attributes": attributes,
            },
        ).raise_for_status()
        clients = http.get(path + "/clients", params={"clientId": API}).raise_for_status().json()
        client_id = clients[0]["id"]
        roles = {
            role["name"]: role
            for role in http.get(path + f"/clients/{client_id}/roles").raise_for_status().json()
        }
        scopes = {
            item["name"]: item["id"] for item in http.get(path + "/client-scopes").raise_for_status().json()
        }
        for name, role in {
            "atomic:read": "viewer",
            "atomic:request": "operator",
            "atomic:cleanup": "operator",
        }.items():
            http.post(
                path + f"/client-scopes/{scopes[name]}/scope-mappings/clients/{client_id}", json=[roles[role]]
            ).raise_for_status()
        from .user_management import enable

        enable(runtime, http=http)
        print("Configured owned Keycloak realm:", values["ATOMIC_OIDC_ISSUER"])
        print(
            "Application roles and scoped MCP token exchange configured; credentials remain in the private runtime directory."
        )


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "up", "provision", "stop", "status", "network"])
    parser.add_argument("--address")
    parser.add_argument("--subnet")
    parser.add_argument(
        "--identity-hostname", help="Resolvable internal DNS name for Keycloak's OAuth issuer"
    )
    parser.add_argument(
        "--public-hostname", help="Resolvable internal DNS name for the dashboard and agent API"
    )
    parser.add_argument("--loopback", action="store_true")
    args = parser.parse_args()
    if (args.identity_hostname or args.public_hostname) and args.action != "network":
        parser.error("Hostname options apply to network configuration")
    if args.action == "network":
        if args.loopback:
            if args.address or args.subnet or args.identity_hostname or args.public_hostname:
                parser.error("--loopback cannot be combined with LAN network options")
            (RUNTIME / "network.json").unlink(missing_ok=True)
        elif not args.address or not args.subnet:
            parser.error("network requires --address and --subnet")
        else:
            network = validate_network(
                args.address, args.subnet, args.identity_hostname, args.public_hostname
            )
            private_write(RUNTIME / "network.json", json.dumps(network, indent=2).encode())
    prepare()
    if args.action == "up":
        compose("up", "-d")
        provision()
    elif args.action == "provision":
        provision()
    elif args.action == "stop":
        compose("stop")
    elif args.action == "status":
        compose("ps")
    else:
        print("Generated private local identity configuration:", RUNTIME)


if __name__ == "__main__":
    main()
