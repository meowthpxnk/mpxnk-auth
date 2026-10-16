"""Unit tests for session issue, refresh, cap, and revoke."""

from pydantic import BaseModel

import pytest
from mpxnk_auth.auth_api.session_cache_store import SessionCacheString
from mpxnk_auth.auth_api.session_service import AuthSessionService
from mpxnk_auth.exceptions import (
    FailedRefreshSession,
    NotFoundSession,
    NotValidTokenType,
)
from mpxnk_auth.schemas import JWTTokenTypeEnum, UserBase

pytestmark = pytest.mark.unit


def _user(auth_api, username: str = "alice", role: str = "user") -> UserBase:
    return auth_api.user_cls(username=username, role=role)


def _session_id(auth_api, token: str) -> str:
    return auth_api.jwt_provider.decode(token).session_id


async def test_create_session_stores_only_the_refresh_token(auth_api) -> None:
    access, refresh = await auth_api.session_service.create_session(
        _user(auth_api)
    )
    session_id = _session_id(auth_api, refresh)
    stored = await auth_api.cache_store.get_token(
        SessionCacheString("alice", session_id)
    )

    decoded = await auth_api.session_service.decode_access_token(access)

    assert stored == refresh
    assert access != refresh
    assert decoded.type is JWTTokenTypeEnum.ACCESS


async def test_refresh_keeps_session_id_and_replaces_the_token(
    auth_api, token_clock
) -> None:
    _access, refresh = await auth_api.session_service.create_session(
        _user(auth_api)
    )
    session_id = _session_id(auth_api, refresh)

    new_access, new_refresh = await auth_api.session_service.refresh_session(
        refresh
    )

    assert new_refresh != refresh
    assert _session_id(auth_api, new_refresh) == session_id
    assert _session_id(auth_api, new_access) == session_id
    stored = await auth_api.cache_store.get_token(
        SessionCacheString("alice", session_id)
    )
    assert stored == new_refresh


async def test_reused_refresh_token_revokes_every_session(
    auth_api, token_clock
) -> None:
    service = auth_api.session_service
    _access, refresh = await service.create_session(_user(auth_api))
    _new_access, new_refresh = await service.refresh_session(refresh)

    with pytest.raises(FailedRefreshSession):
        await service.refresh_session(refresh)

    assert await auth_api.cache_store.count_tokens("alice") == 0
    with pytest.raises(NotFoundSession):
        await service.refresh_session(new_refresh)

    latest_access, latest_refresh = await service.create_session(
        _user(auth_api)
    )
    assert latest_access
    assert (
        await auth_api.cache_store.get_token(
            SessionCacheString("alice", _session_id(auth_api, latest_refresh))
        )
        == latest_refresh
    )


async def test_missing_refresh_does_not_revoke_other_sessions(
    auth_api,
) -> None:
    service = auth_api.session_service
    _access_a, refresh_a = await service.create_session(_user(auth_api))
    _access_b, refresh_b = await service.create_session(_user(auth_api))
    session_a = _session_id(auth_api, refresh_a)
    session_b = _session_id(auth_api, refresh_b)
    await service.revoke_session(SessionCacheString("alice", session_a))

    with pytest.raises(NotFoundSession):
        await service.refresh_session(refresh_a)

    assert (
        await auth_api.cache_store.get_token(
            SessionCacheString("alice", session_b)
        )
        == refresh_b
    )


async def test_access_token_cannot_refresh_a_session(auth_api) -> None:
    service = auth_api.session_service
    access, refresh = await service.create_session(_user(auth_api))
    session_id = _session_id(auth_api, refresh)

    with pytest.raises(NotValidTokenType):
        await service.refresh_session(access)

    assert (
        await auth_api.cache_store.get_token(
            SessionCacheString("alice", session_id)
        )
        == refresh
    )


async def test_revoked_access_token_is_rejected_without_touching_others(
    auth_api,
) -> None:
    service = auth_api.session_service
    access, _refresh = await service.create_session(_user(auth_api))
    other_access, other_refresh = await service.create_session(
        _user(auth_api)
    )
    session_id = _session_id(auth_api, access)
    other_id = _session_id(auth_api, other_access)

    await service.revoke_session(SessionCacheString("alice", session_id))

    with pytest.raises(NotFoundSession) as exc:
        await service.decode_access_token(access)

    decoded = await service.decode_access_token(other_access)

    assert exc.value.username == "alice"
    assert exc.value.session_id == session_id
    assert decoded.session_id == other_id
    assert decoded.type is JWTTokenTypeEnum.ACCESS
    assert (
        await auth_api.cache_store.get_token(
            SessionCacheString("alice", other_id)
        )
        == other_refresh
    )


async def test_refresh_token_cannot_be_read_as_access(auth_api) -> None:
    _access, refresh = await auth_api.session_service.create_session(
        _user(auth_api)
    )

    with pytest.raises(NotValidTokenType):
        await auth_api.session_service.decode_access_token(refresh)


async def test_session_cap_keeps_the_newest_sessions(
    make_auth_api, token_clock
) -> None:
    api, _redis = make_auth_api(max_user_sessions=2)
    service = api.session_service
    created = [await service.create_session(_user(api)) for _ in range(4)]
    live = {_session_id(api, refresh) for _access, refresh in created[-2:]}
    evicted = {_session_id(api, refresh) for _access, refresh in created[:2]}

    assert await api.cache_store.count_tokens("alice") == 2
    for session_id in live:
        assert await api.cache_store.get_token(
            SessionCacheString("alice", session_id)
        )
    for session_id in evicted:
        with pytest.raises(NotFoundSession):
            await api.cache_store.get_token(
                SessionCacheString("alice", session_id)
            )


async def test_refresh_makes_a_session_newer_than_an_idle_one(
    make_auth_api, token_clock
) -> None:
    api, _redis = make_auth_api(max_user_sessions=2)
    service = api.session_service
    _access_a, refresh_a = await service.create_session(_user(api))
    _access_b, refresh_b = await service.create_session(_user(api))
    _rotated_access, refresh_a = await service.refresh_session(refresh_a)
    _access_c, refresh_c = await service.create_session(_user(api))

    assert await api.cache_store.count_tokens("alice") == 2
    with pytest.raises(NotFoundSession):
        await api.cache_store.get_token(
            SessionCacheString("alice", _session_id(api, refresh_b))
        )
    assert await api.cache_store.get_token(
        SessionCacheString("alice", _session_id(api, refresh_a))
    )
    assert await api.cache_store.get_token(
        SessionCacheString("alice", _session_id(api, refresh_c))
    )


def test_get_last_sessions_orders_by_exp(auth_api) -> None:
    data_cls = auth_api.data_cls
    sessions = [
        data_cls.model_validate(
            {
                "username": "alice",
                "role": "user",
                "session_id": session_id,
                "exp": exp,
                "type": "REFRESH",
            }
        )
        for session_id, exp in (("new", 300), ("old", 100), ("mid", 200))
    ]

    closed = AuthSessionService._get_last_sessions(sessions, 2)

    assert [item.session_id for item in closed] == ["old", "mid"]


async def test_revoke_all_except_current(auth_api) -> None:
    service = auth_api.session_service
    _access, refresh = await service.create_session(_user(auth_api))
    await service.create_session(_user(auth_api))
    session_id = _session_id(auth_api, refresh)

    await service.revoke_all_sessions("alice", exclude_session_id=session_id)

    assert await service.cache_store.count_tokens("alice") == 1
    assert (
        await service.cache_store.get_token(
            SessionCacheString("alice", session_id)
        )
        == refresh
    )


async def test_revoke_all_does_not_touch_another_user(auth_api) -> None:
    service = auth_api.session_service
    await service.create_session(_user(auth_api))
    _access, bob_refresh = await service.create_session(
        _user(auth_api, username="bob", role="admin")
    )

    await service.revoke_all_sessions("alice")

    assert await service.cache_store.count_tokens("alice") == 0
    assert (
        await service.cache_store.get_token(
            SessionCacheString("bob", _session_id(auth_api, bob_refresh))
        )
        == bob_refresh
    )


async def test_create_session_rejects_unknown_model(auth_api) -> None:
    class Other(BaseModel):
        username: str

    with pytest.raises(TypeError, match="UserSchema"):
        await auth_api.session_service.create_session(Other(username="alice"))


def test_payload_to_userdata_drops_jwt_claims(auth_api) -> None:
    payload = auth_api.data_cls.model_validate(
        {
            "username": "alice",
            "role": "admin",
            "session_id": "sid",
            "exp": 10,
            "type": "ACCESS",
        }
    )

    user = auth_api.session_service.payload_to_userdata(payload)

    assert user.model_dump() == {"username": "alice", "role": "admin"}
