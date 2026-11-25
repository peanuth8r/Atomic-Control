import ssl

import pytest

from apps.agent import job_client as tls


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_agent_uses_system_ca_store_without_disabling_verification(monkeypatch, platform):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    original = ssl.create_default_context
    native = original()
    monkeypatch.setattr(tls.sys, "platform", platform)
    calls = []

    def context(**kwargs):
        calls.append(kwargs)
        return native

    monkeypatch.setattr(tls.ssl, "create_default_context", context)
    configured = tls.tls_verification()
    assert calls == [{"cafile": None, "capath": None}]
    assert configured.verify_mode == ssl.CERT_REQUIRED and configured.check_hostname


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_agent_loads_the_explicit_private_ca_and_rejects_invalid_bundles(tmp_path, monkeypatch, platform):
    from apps.local_identity.setup import prepare

    prepare(tmp_path)
    monkeypatch.setattr(tls.sys, "platform", platform)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "tls/ca.pem"))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    context = tls.tls_verification()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.cert_store_stats()["x509_ca"] == 1
    (tmp_path / "invalid.pem").write_text("invalid certificate")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "invalid.pem"))
    with pytest.raises(ssl.SSLError):
        tls.tls_verification()


def test_other_platform_retains_httpx_verified_defaults(monkeypatch):
    monkeypatch.setattr(tls.sys, "platform", "darwin")
    assert tls.tls_verification() is True
