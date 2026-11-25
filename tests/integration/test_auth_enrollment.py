from fastapi.testclient import TestClient

from apps.api.app.auth import Principal, human
from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import Base


def test_enrollment_single_use_scoped_and_distinct_credentials(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/real.db",
        mode="real",
        dev_auth=False,
        signing_key_file="not-used-in-enrollment.pem",
        oidc_issuer="https://id.example.invalid",
        oidc_jwks_url="https://id.example.invalid/jwks",
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    app.dependency_overrides[human] = lambda: Principal(
        "administrator", frozenset({"administrator", "viewer"}), frozenset()
    )
    c = TestClient(app)
    tokens = []
    for hostname in ["WIN-01", "WIN-02"]:
        token = c.post("/api/v1/enrollment-tokens", json={"hostname": hostname}).json()["token"]
        body = {"token": token, "hostname": hostname, "agent_version": "0.1.0", "os_version": "Windows 11"}
        mismatch = c.post("/api/v1/agents/enroll", json={**body, "hostname": "WRONG"})
        assert mismatch.status_code == 401
        registered = c.post("/api/v1/agents/enroll", json=body)
        assert registered.status_code == 200, registered.text
        credential = registered.json()["credential"]
        tokens.append(credential)
        assert c.post("/api/v1/agents/enroll", json=body).status_code == 401
        assert (
            c.post("/api/v1/agents/jobs/claim", headers={"Authorization": "Bearer " + token}).status_code
            == 401
        )
        heartbeat = c.post(
            "/api/v1/agents/heartbeat",
            headers={"Authorization": "Bearer " + credential},
            json={
                "hostname": hostname,
                "agent_version": "0.1.0",
                "os_version": "Windows 11",
                "revision": "pinned",
                "profiles": {},
                "health": "healthy",
            },
        )
        assert heartbeat.status_code == 200
        assert (
            c.post(
                "/api/v1/agents/heartbeat",
                headers={"Authorization": "Bearer " + credential},
                json={
                    "hostname": "WRONG",
                    "agent_version": "0.1.0",
                    "os_version": "Windows 11",
                    "revision": "pinned",
                    "profiles": {},
                    "health": "healthy",
                },
            ).status_code
            == 403
        )
    assert tokens[0] != tokens[1]


def test_mcp_role_claims_cannot_escalate(env, request_job, monkeypatch):
    from apps.api.app import auth

    env["app"].state.settings.dev_auth = False
    env["app"].state.settings.oidc_issuer = "https://id.example.invalid"
    monkeypatch.setattr(
        auth,
        "verify_oidc",
        lambda *_: {
            "sub": "mcp-caller",
            "scope": "atomic:read atomic:request",
            "roles": ["administrator", "approver", "privileged_approver"],
        },
    )
    response = env["client"].get("/api/v1/me", headers={"Authorization": "Bearer placeholder"})
    assert set(response.json()["roles"]) == {"viewer", "operator"}
    assert (
        env["client"]
        .post(
            "/api/v1/enrollment-tokens",
            headers={"Authorization": "Bearer placeholder"},
            json={"hostname": "WIN-03"},
        )
        .status_code
        == 403
    )


def test_non_mcp_oidc_role_without_azp_remains_human(env, monkeypatch):
    from apps.api.app import auth

    env["app"].state.settings.dev_auth = False
    env["app"].state.settings.oidc_issuer = "https://id.example.invalid"
    monkeypatch.setattr(
        auth, "verify_oidc", lambda *_: {"sub": "human", "scope": "openid", "roles": ["viewer", "approver"]}
    )
    response = env["client"].get("/api/v1/me", headers={"Authorization": "Bearer placeholder"})
    assert set(response.json()["roles"]) == {"viewer", "approver"}
