"""Unit tests for RS256 access and refresh tokens."""

import jwt

import pytest
from mpxnk_auth.schemas import JWTTokenTypeEnum, TokenPayloadBase

pytestmark = pytest.mark.unit


def _payload(auth_api, session_id: str = "sid") -> TokenPayloadBase:
    return auth_api.payload_cls(
        username="alice",
        role="user",
        session_id=session_id,
    )


def test_encode_returns_access_and_refresh_pair(auth_api) -> None:
    access, refresh = auth_api.jwt_provider.encode(_payload(auth_api))

    access_data = auth_api.jwt_provider.decode(access)
    refresh_data = auth_api.jwt_provider.decode(refresh)

    assert access != refresh
    assert access_data.type is JWTTokenTypeEnum.ACCESS
    assert refresh_data.type is JWTTokenTypeEnum.REFRESH
    assert access_data.username == "alice"
    assert access_data.role == "user"
    assert access_data.session_id == refresh_data.session_id == "sid"
    assert refresh_data.exp - access_data.exp == (
        auth_api.settings.refresh_ttl - auth_api.settings.access_ttl
    )


def test_encode_rejects_a_user_model(auth_api) -> None:
    user = auth_api.user_cls(username="alice", role="user")

    with pytest.raises(TypeError, match="payload"):
        auth_api.jwt_provider.encode(user)


def test_decode_rejects_expired_access_token(make_auth_api) -> None:
    api, _redis = make_auth_api(access_ttl=-30)
    access, _refresh = api.jwt_provider.encode(_payload(api))

    with pytest.raises(jwt.ExpiredSignatureError):
        api.jwt_provider.decode(access)


def test_decode_rejects_tampered_signature(auth_api) -> None:
    access, _refresh = auth_api.jwt_provider.encode(_payload(auth_api))
    broken = access[:-2] + ("aa" if not access.endswith("aa") else "bb")

    with pytest.raises(jwt.InvalidTokenError):
        auth_api.jwt_provider.decode(broken)


def test_decode_rejects_token_from_another_key(
    make_auth_api, foreign_keys_dir
) -> None:
    issuer, _redis = make_auth_api()
    reader, _other_redis = make_auth_api(keys_dir=foreign_keys_dir)
    access, _refresh = issuer.jwt_provider.encode(_payload(issuer))

    with pytest.raises(jwt.InvalidTokenError):
        reader.jwt_provider.decode(access)
