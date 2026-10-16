"""Unit tests for the Redis session cache."""

import pytest
from mpxnk_auth.auth_api.session_cache_store import (
    CacheStore,
    SessionCacheString,
)
from mpxnk_auth.exceptions import NotFoundSession

pytestmark = pytest.mark.unit


def _session(
    username: str = "alice", session_id: str = "sid"
) -> SessionCacheString:
    return SessionCacheString(username, session_id)


async def test_session_key_pattern() -> None:
    session = _session()

    assert session.key == "userSession.alice.sid"
    assert SessionCacheString.get_all_keys("alice") == "userSession.alice.*"


async def test_set_and_get_roundtrip(fake_redis_cls) -> None:
    redis = fake_redis_cls()
    store = CacheStore(redis)
    session = _session()

    await store.set_token(session, "refresh-jwt", 900)

    assert await store.get_token(session) == "refresh-jwt"
    assert redis.expirations[session.key] == 900


async def test_get_missing_session_raises(fake_redis_cls) -> None:
    store = CacheStore(fake_redis_cls())

    with pytest.raises(NotFoundSession) as exc:
        await store.get_token(_session())

    assert exc.value.username == "alice"
    assert exc.value.session_id == "sid"


async def test_remove_token_deletes_existing_session(fake_redis_cls) -> None:
    redis = fake_redis_cls()
    store = CacheStore(redis)
    session = _session()
    await store.set_token(session, "refresh-jwt", 10)

    await store.remove_token(session)

    assert session.key not in redis.store
    with pytest.raises(NotFoundSession):
        await store.remove_token(session)


async def test_remove_all_keeps_other_users_and_excluded_session(
    fake_redis_cls,
) -> None:
    redis = fake_redis_cls()
    store = CacheStore(redis)
    current = _session(session_id="current")
    other = _session(session_id="other")
    bob = _session(username="bob", session_id="bob-sid")
    await store.set_token(current, "current-token", 10)
    await store.set_token(other, "other-token", 10)
    await store.set_token(bob, "bob-token", 10)

    await store.remove_all_tokens("alice", exclude_session_id="current")

    assert await store.get_token(current) == "current-token"
    assert await store.get_token(bob) == "bob-token"
    with pytest.raises(NotFoundSession):
        await store.get_token(other)
    assert await store.count_tokens("alice") == 1
    assert await store.count_tokens("bob") == 1


async def test_remove_all_without_exclude_clears_the_user(
    fake_redis_cls,
) -> None:
    store = CacheStore(fake_redis_cls())
    await store.set_token(_session(session_id="a"), "a", 10)
    await store.set_token(_session(session_id="b"), "b", 10)

    await store.remove_all_tokens("alice")

    assert await store.count_tokens("alice") == 0


async def test_bytes_redis_values_are_decoded(fake_redis_cls) -> None:
    redis = fake_redis_cls(decode_responses=False)
    store = CacheStore(redis)
    keep = _session(session_id="keep")
    drop = _session(session_id="drop")
    await store.set_token(keep, "keep-token", 10)
    await store.set_token(drop, "drop-token", 10)

    assert await store.get_token(keep) == "keep-token"
    await store.remove_all_tokens("alice", exclude_session_id="keep")

    assert await store.get_token(keep) == "keep-token"
    with pytest.raises(NotFoundSession):
        await store.get_token(drop)


def test_as_str_normalizes_bytes() -> None:
    assert CacheStore._as_str(b"token") == "token"
    assert CacheStore._as_str("token") == "token"


async def test_session_id_exists_follows_the_redis_key(
    fake_redis_cls,
) -> None:
    store = CacheStore(fake_redis_cls())
    session = _session()
    await store.set_token(session, "refresh-jwt", 10)

    assert await store.session_id_exists("alice", "sid") is True
    assert await store.session_id_exists("alice", "other") is False
    assert await store.session_id_exists("bob", "sid") is False

    await store.remove_token(session)

    assert await store.session_id_exists("alice", "sid") is False


async def test_session_id_exists_accepts_bytes_values(fake_redis_cls) -> None:
    store = CacheStore(fake_redis_cls(decode_responses=False))
    await store.set_token(_session(), "refresh-jwt", 10)

    assert await store.session_id_exists("alice", "sid") is True
