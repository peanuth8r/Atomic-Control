import json

import httpx
import pytest
from dotenv import dotenv_values

from apps.local_identity import user_management as setup
from apps.local_identity.setup import private_write


def test_enabling_user_management_preserves_existing_environment_and_credentials(tmp_path, monkeypatch):
    credentials = {
        "owner_id": "fixture-owner",
        "bootstrap_password": "fixture-secret",
        "users": {"kept": "unchanged"},
    }
    private_write(tmp_path / "credentials.json", json.dumps(credentials).encode())
    private_write(
        tmp_path / "application.env",
        b'ATOMIC_OIDC_ISSUER="https://identity.example.test/realms/atomic-control"\nATOMIC_ALLOWED_SUBNET="0.0.0.0/0"\nATOMIC_APPROVAL_MODE="per_run"\nATOMIC_PUBLIC_URL="https://control.example.test"\n',
    )
    before = dotenv_values(tmp_path / "application.env", interpolate=False)
    calls = []
    monkeypatch.setattr(setup, "provision_client", lambda *args: calls.append(args))
    client = object()
    setup.enable(tmp_path, http=client)
    first = json.loads((tmp_path / "credentials.json").read_text())
    assert {key: first[key] for key in credentials} == credentials
    assert len(first["user_management_secret"]) >= 32
    after = dotenv_values(tmp_path / "application.env", interpolate=False)
    assert all(after[key] == value for key, value in before.items())
    assert after["ATOMIC_KEYCLOAK_MANAGEMENT_CLIENT_SECRET"] == first["user_management_secret"]
    assert after["ATOMIC_USER_MANAGEMENT_PROVIDER"] == "keycloak"
    assert calls[0][0] is client
    assert calls[0][1] == "https://identity.example.test/admin/realms/atomic-control"
    setup.enable(tmp_path, http=client)
    assert json.loads((tmp_path / "credentials.json").read_text()) == first
    assert (tmp_path / "application.env").read_text().count("ATOMIC_USER_MANAGEMENT_PROVIDER=") == 1
    assert (tmp_path / "credentials.json").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "application.env").stat().st_mode & 0o777 == 0o600


def test_setup_refuses_unprotected_configuration(tmp_path):
    (tmp_path / "credentials.json").write_text("{}")
    (tmp_path / "credentials.json").chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        setup.enable(tmp_path)


def test_setup_never_adopts_an_unowned_realm():
    calls = []

    def handle(request):
        calls.append(request.method)
        return httpx.Response(200, json={"attributes": {"atomic-control-owner": "somebody-else"}})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError, match="unrelated Keycloak realm"):
            setup.provision_client(
                client, "https://identity.example.test/admin/realms/atomic-control", "owner", "secret"
            )
    assert calls == ["GET"]
