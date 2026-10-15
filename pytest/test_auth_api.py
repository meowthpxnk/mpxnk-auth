"""Unit tests for the AuthAPI facade."""

from fastapi import Response

import pytest
from mpxnk_auth.auth_api.session_cache_store import SessionCacheString
from mpxnk_auth.constants import REFRESH_TOKEN_COOKIE
from mpxnk_auth.schemas import JWTTokenTypeEnum

pytestmark = pytest.mark.unit


def test_auth_api_wires_settings_and_user_model(make_auth_api) -> None:
    api, redis = make_auth_api(max_user_sessions=3, access_ttl=15)

    assert api.user_cls.__name__ == "UserSchema"
    assert api.settings.max_user_sessions == 3
    assert api.settings.access_ttl == 15
    assert api.tags == ["auth"]
    assert api.cache_store.redis is redis
    assert api.session_service.jwt_provider is api.jwt_provider
    assert "role" in api.payload_cls.model_fields


async def test_issue_session_returns_access_and_sets_refresh_cookie(
    auth_api,
) -> None:
    response = Response()
    user = auth_api.user_cls(username="alice", role="user")

    result = await auth_api.issue_session(user, response)

    header = response.headers["set-cookie"]
    cookie = header.split(";", 1)[0].split("=", 1)[1]
    refresh_data = auth_api.jwt_provider.decode(cookie)
    access_data = auth_api.jwt_provider.decode(result.access_token)
    stored = await auth_api.cache_store.get_token(
        SessionCacheString(user.username, refresh_data.session_id)
    )
    folded = header.casefold()

    assert result.access_token != cookie
    assert stored == cookie
    assert access_data.type is JWTTokenTypeEnum.ACCESS
    assert refresh_data.type is JWTTokenTypeEnum.REFRESH
    assert access_data.session_id == refresh_data.session_id
    assert folded.startswith(f"{REFRESH_TOKEN_COOKIE}={cookie}".casefold())
    assert "httponly" in folded
    assert "secure" in folded
    assert "samesite=none" in folded
    assert f"max-age={auth_api.settings.refresh_ttl}" in folded
