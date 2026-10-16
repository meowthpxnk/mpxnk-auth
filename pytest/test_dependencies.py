"""Unit tests for FastAPI auth dependencies."""

from types import SimpleNamespace
from typing import get_type_hints

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

import pytest
from mpxnk_auth.fastapi.dependencies import (
    bearer,
    get_auth_api,
    get_current_token,
    get_refresh_token,
    get_session_service,
    get_user,
    read_access_token,
)
from mpxnk_auth.schemas import JWTTokenTypeEnum

pytestmark = pytest.mark.unit


def test_get_auth_api_reads_application_state(auth_api) -> None:
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(auth_api=auth_api))
    )

    assert get_auth_api(request) is auth_api
    assert get_session_service(auth_api) is auth_api.session_service


def test_get_refresh_token_reads_cookie() -> None:
    present = SimpleNamespace(cookies={"Refresh-Token": "jwt"})
    missing = SimpleNamespace(cookies={})

    assert get_refresh_token(present) == "jwt"
    assert get_refresh_token(missing) is None


def test_bearer_dependency_is_not_recursive() -> None:
    credentials = get_type_hints(get_current_token, include_extras=True)[
        "credentials"
    ]
    token = get_type_hints(read_access_token, include_extras=True)[
        "bearer_token"
    ]

    assert credentials.__metadata__[0].dependency is bearer
    assert token.__metadata__[0].dependency is get_current_token


async def test_get_current_token_returns_bearer_credentials() -> None:
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="access-jwt"
    )

    assert await get_current_token(credentials) == "access-jwt"


async def test_read_access_token_returns_payload(auth_api) -> None:
    user = auth_api.user_cls(username="alice", role="admin")
    access, _refresh = await auth_api.session_service.create_session(user)

    payload = await read_access_token(auth_api.session_service, access)

    assert payload.username == "alice"
    assert payload.role == "admin"
    assert payload.type is JWTTokenTypeEnum.ACCESS
    assert get_user(auth_api.session_service, payload).model_dump() == {
        "username": "alice",
        "role": "admin",
    }


async def test_read_access_token_rejects_garbage(auth_api) -> None:
    with pytest.raises(HTTPException) as exc:
        await read_access_token(auth_api.session_service, "not-a-jwt")

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"
