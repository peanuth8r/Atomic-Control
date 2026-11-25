"""Establish a process-local test environment before application imports."""

import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# This process-only environment is established before importing the application.
_bootstrap = tempfile.TemporaryDirectory(prefix="atomic-tests-")
_signer = Path(_bootstrap.name) / "signer.pem"
_signer.write_bytes(
    rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
)
for _key, _value in {
    "ATOMIC_MODE": "real",
    "ATOMIC_DEV_AUTH": "false",
    "ATOMIC_OIDC_ISSUER": "https://id.example.test",
    "ATOMIC_OIDC_JWKS_URL": "https://id.example.test/jwks",
    "ATOMIC_SIGNING_KEY_FILE": str(_signer),
    "ATOMIC_DATABASE_URL": "sqlite:///" + _bootstrap.name + "/bootstrap.db",
}.items():
    os.environ[_key] = _value


def configure_environment():
    return _signer
