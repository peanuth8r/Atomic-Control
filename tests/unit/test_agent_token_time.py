"""Token timing regression checks with real signatures and simulated agent clocks."""

from datetime import datetime

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.api.app.services.token_time import ISSUED_AT_BACKDATE_SECONDS, token_issued_at

SERVER_TIME = 1795536494.269750
AGENT_TIME = 1795536493.691977


@pytest.fixture(scope="module")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def clock_at(monkeypatch, timestamp):
    class AgentClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(timestamp, tz)

    monkeypatch.setattr(jwt.api_jwt, "datetime", AgentClock)


def decode(keys, **changes):
    claims = {
        "iss": "atomic-control",
        "aud": "fixture-actor",
        "iat": token_issued_at(SERVER_TIME),
        "exp": int(SERVER_TIME + 60),
        **changes,
    }
    token = jwt.encode(claims, keys[0], algorithm="RS256")
    return jwt.decode(
        token,
        keys[1],
        algorithms=["RS256"],
        issuer="atomic-control",
        audience="fixture-actor",
        options={"require": ["exp", "iat", "iss", "aud"]},
    )


def test_observed_subsecond_clock_difference_reproduces_old_failure(keys, monkeypatch):
    clock_at(monkeypatch, AGENT_TIME)
    with pytest.raises(jwt.ImmatureSignatureError):
        decode(keys, iat=int(SERVER_TIME))


@pytest.mark.parametrize("behind", [0, 0.6, 2, 5])
def test_backdated_issuance_accepts_small_clock_offsets_without_changing_expiry(keys, monkeypatch, behind):
    clock_at(monkeypatch, SERVER_TIME - behind)
    claims = decode(keys)
    assert claims["iat"] == int(SERVER_TIME) - ISSUED_AT_BACKDATE_SECONDS
    assert claims["exp"] == int(SERVER_TIME + 60)


def test_larger_clock_offset_still_fails_closed(keys, monkeypatch):
    clock_at(monkeypatch, SERVER_TIME - 6)
    with pytest.raises(jwt.ImmatureSignatureError):
        decode(keys)


def test_expiration_remains_strict_even_within_five_seconds(keys, monkeypatch):
    clock_at(monkeypatch, AGENT_TIME)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode(keys, exp=int(AGENT_TIME) - 1)


@pytest.mark.parametrize(
    "claim,value,error",
    [
        ("aud", "other-actor", jwt.InvalidAudienceError),
        ("iss", "other-issuer", jwt.InvalidIssuerError),
        ("nbf", int(SERVER_TIME + 1), jwt.ImmatureSignatureError),
    ],
)
def test_other_claim_checks_remain_enabled(keys, monkeypatch, claim, value, error):
    clock_at(monkeypatch, AGENT_TIME)
    with pytest.raises(error):
        decode(keys, **{claim: value})
