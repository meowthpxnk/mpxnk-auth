"""Unit tests for JWTAuthSettings."""

import pytest
from mpxnk_auth.settings import JWTAuthSettings

pytestmark = pytest.mark.unit

_ENV_NAMES = (
    "ACCESS_TOKEN_TTL",
    "REFRESH_TOKEN_TTL",
    "MAX_USER_SESSIONS",
    "JWT_KEYS_PATH",
    "JWT_ALGORITHM",
)


def test_defaults_when_env_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    settings = JWTAuthSettings()

    assert settings.access_ttl == 900
    assert settings.refresh_ttl == 2_419_200
    assert settings.max_user_sessions == 5
    assert settings.keys_path == "jwt_keys"
    assert settings.algorithm == "RS256"


def test_constructor_uses_env_aliases() -> None:
    settings = JWTAuthSettings(
        ACCESS_TOKEN_TTL=15,
        REFRESH_TOKEN_TTL=60,
        MAX_USER_SESSIONS=2,
        JWT_KEYS_PATH="keys",
        JWT_ALGORITHM="RS256",
    )

    assert settings.access_ttl == 15
    assert settings.refresh_ttl == 60
    assert settings.max_user_sessions == 2
    assert settings.keys_path == "keys"
    assert settings.algorithm == "RS256"


def test_environment_overrides_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCESS_TOKEN_TTL", "42")
    monkeypatch.setenv("MAX_USER_SESSIONS", "3")
    monkeypatch.setenv("JWT_KEYS_PATH", "from-env")

    settings = JWTAuthSettings()

    assert settings.access_ttl == 42
    assert settings.max_user_sessions == 3
    assert settings.keys_path == "from-env"
