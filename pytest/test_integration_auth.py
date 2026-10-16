"""Integration tests for the FastAPI auth routes."""

import jwt
from httpx import Response

import pytest
from mpxnk_auth.auth_api.session_cache_store import SessionCacheString
from mpxnk_auth.exceptions import (
    FailedRefreshSession,
    NotFoundSession,
    NotValidTokenType,
)

pytestmark = pytest.mark.integration


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _refresh_cookie(response) -> str:
    if "Refresh-Token" in response.cookies:
        return response.cookies["Refresh-Token"]
    header = response.headers["set-cookie"]
    return header.split(";", 1)[0].split("=", 1)[1]


def _session_id(auth_api, token: str) -> str:
    return auth_api.jwt_provider.decode(token).session_id


def _set_refresh(client, token: str) -> None:
    client.cookies.clear()
    client.cookies.set("Refresh-Token", token)


async def _login(
    client, username: str = "alice", password: str = "secret"
) -> Response:
    response = await client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response


async def test_login_returns_bearer_and_refresh_cookie(make_client) -> None:
    client, redis, auth_api = await make_client()

    response = await _login(client)
    body = response.json()
    refresh = _refresh_cookie(response)
    header = response.headers["set-cookie"].casefold()
    session_id = _session_id(auth_api, body["access_token"])

    assert set(body) == {"access_token"}
    assert refresh != body["access_token"]
    assert "httponly" in header
    assert "secure" in header
    assert "samesite=none" in header
    assert f"max-age={auth_api.settings.refresh_ttl}" in header
    assert await redis.get(f"userSession.alice.{session_id}") == refresh


@pytest.mark.parametrize(
    ("username", "password"),
    [("alice", "wrong"), ("nobody", "secret")],
)
async def test_login_rejects_bad_credentials(
    make_client, username: str, password: str
) -> None:
    client, redis, _auth_api = await make_client()

    response = await client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"
    assert await redis.keys("userSession.*") == []


async def test_me_and_closed_route_require_a_valid_access_token(
    make_client,
) -> None:
    client, _redis, _auth_api = await make_client()
    login = await _login(client, username="bob")
    access = login.json()["access_token"]

    me = await client.get("/auth/me", headers=_bearer(access))
    closed = await client.get("/closed", headers=_bearer(access))
    missing = await client.get("/auth/me")
    garbage = await client.get("/auth/me", headers=_bearer("not-a-jwt"))
    none_alg = "eyJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFsaWNlIn0."
    forged = await client.get("/auth/me", headers=_bearer(none_alg))

    assert me.status_code == 200
    assert me.json() == {"username": "bob", "role": "admin"}
    assert closed.status_code == 200
    assert closed.json() == {"ok": True}
    assert missing.status_code == 401
    assert missing.json()["detail"] == "Not authenticated"
    assert garbage.status_code == 401
    assert garbage.json()["detail"] == "Invalid token"
    assert forged.status_code == 401
    assert forged.json()["detail"] == "Invalid token"


async def test_refresh_rotates_the_cookie_and_keeps_the_session(
    make_client, token_clock
) -> None:
    client, redis, auth_api = await make_client()
    login = await _login(client)
    old_access = login.json()["access_token"]
    old_refresh = _refresh_cookie(login)
    _set_refresh(client, old_refresh)

    refreshed = await client.post("/auth/refresh-token")

    assert refreshed.status_code == 200, refreshed.text
    new_access = refreshed.json()["access_token"]
    new_refresh = _refresh_cookie(refreshed)
    session_id = _session_id(auth_api, new_access)
    me = await client.get("/auth/me", headers=_bearer(new_access))

    assert new_access != old_access
    assert new_refresh != old_refresh
    assert session_id == _session_id(auth_api, old_access)
    assert me.status_code == 200
    assert await redis.get(f"userSession.alice.{session_id}") == new_refresh


async def test_reused_refresh_cookie_revokes_all_sessions(
    make_client, token_clock
) -> None:
    client, redis, auth_api = await make_client()
    first = await _login(client)
    old_refresh = _refresh_cookie(first)
    _set_refresh(client, old_refresh)
    rotated = await client.post("/auth/refresh-token")
    new_refresh = _refresh_cookie(rotated)
    assert new_refresh != old_refresh

    _set_refresh(client, old_refresh)
    with pytest.raises(FailedRefreshSession):
        await client.post("/auth/refresh-token")

    _set_refresh(client, new_refresh)
    with pytest.raises(NotFoundSession):
        await client.post("/auth/refresh-token")

    login_again = await _login(client)

    assert await redis.keys("userSession.alice.*") == [
        "userSession.alice."
        + _session_id(auth_api, login_again.json()["access_token"])
    ]


async def test_logout_removes_only_the_current_session(make_client) -> None:
    client, redis, auth_api = await make_client()
    first = await _login(client)
    second = await _login(client)
    first_access = first.json()["access_token"]
    second_access = second.json()["access_token"]
    first_id = _session_id(auth_api, first_access)
    second_id = _session_id(auth_api, second_access)

    logout = await client.post("/auth/logout", headers=_bearer(first_access))
    revoked = await client.get("/auth/me", headers=_bearer(first_access))
    kept = await client.get("/auth/me", headers=_bearer(second_access))

    assert logout.status_code == 200
    assert revoked.status_code == 401
    assert revoked.json()["detail"] == "Invalid token"
    assert kept.status_code == 200
    assert kept.json() == {"username": "alice", "role": "user"}
    assert await redis.get(f"userSession.alice.{first_id}") is None
    assert await redis.get(f"userSession.alice.{second_id}") == (
        _refresh_cookie(second)
    )


async def test_revoke_all_sessions_clears_the_user(make_client) -> None:
    client, redis, auth_api = await make_client()
    alice = await _login(client)
    bob = await _login(client, username="bob")

    alice_access = alice.json()["access_token"]
    bob_access = bob.json()["access_token"]
    response = await client.post(
        "/auth/revoke-all-sessions",
        headers=_bearer(alice_access),
    )
    alice_me = await client.get("/auth/me", headers=_bearer(alice_access))
    bob_me = await client.get("/auth/me", headers=_bearer(bob_access))

    assert response.status_code == 200
    assert alice_me.status_code == 401
    assert alice_me.json()["detail"] == "Invalid token"
    assert bob_me.status_code == 200
    assert bob_me.json() == {"username": "bob", "role": "admin"}
    assert await redis.keys("userSession.alice.*") == []
    assert await redis.get(
        "userSession.bob." + _session_id(auth_api, bob_access)
    ) == _refresh_cookie(bob)


async def test_revoke_all_except_current_keeps_one_session(
    make_client,
) -> None:
    client, redis, auth_api = await make_client()
    current = await _login(client)
    other = await _login(client)
    current_access = current.json()["access_token"]
    current_id = _session_id(auth_api, current_access)
    other_id = _session_id(auth_api, other.json()["access_token"])

    response = await client.post(
        "/auth/revoke-all-sessions-except-current",
        headers=_bearer(current_access),
    )
    _set_refresh(client, _refresh_cookie(current))
    refreshed = await client.post("/auth/refresh-token")

    assert response.status_code == 200
    assert refreshed.status_code == 200, refreshed.text
    assert await redis.get(f"userSession.alice.{other_id}") is None
    assert await redis.get(f"userSession.alice.{current_id}") == (
        _refresh_cookie(refreshed)
    )


async def test_sixth_login_evicts_the_oldest_session(
    make_client, token_clock
) -> None:
    client, _redis, auth_api = await make_client(max_user_sessions=2)
    created = [await _login(client) for _ in range(3)]
    session_ids = [
        _session_id(auth_api, response.json()["access_token"])
        for response in created
    ]

    assert await auth_api.cache_store.count_tokens("alice") == 2
    with pytest.raises(NotFoundSession):
        await auth_api.cache_store.get_token(
            SessionCacheString("alice", session_ids[0])
        )
    assert await auth_api.cache_store.get_token(
        SessionCacheString("alice", session_ids[1])
    )
    assert await auth_api.cache_store.get_token(
        SessionCacheString("alice", session_ids[2])
    )


async def test_refresh_of_idle_session_is_evicted_before_a_used_one(
    make_client, token_clock
) -> None:
    client, _redis, auth_api = await make_client(max_user_sessions=2)
    first = await _login(client)
    idle = await _login(client)
    _set_refresh(client, _refresh_cookie(first))
    await client.post("/auth/refresh-token")
    newest = await _login(client)

    with pytest.raises(NotFoundSession):
        await auth_api.cache_store.get_token(
            SessionCacheString(
                "alice",
                _session_id(auth_api, idle.json()["access_token"]),
            )
        )
    assert await auth_api.cache_store.get_token(
        SessionCacheString(
            "alice",
            _session_id(auth_api, first.json()["access_token"]),
        )
    )
    assert await auth_api.cache_store.get_token(
        SessionCacheString(
            "alice",
            _session_id(auth_api, newest.json()["access_token"]),
        )
    )


async def test_access_token_is_rejected_as_a_refresh_cookie(
    make_client,
) -> None:
    client, redis, auth_api = await make_client()
    login = await _login(client)
    access = login.json()["access_token"]

    _set_refresh(client, access)
    with pytest.raises(NotValidTokenType):
        await client.post("/auth/refresh-token")

    assert await redis.get(
        "userSession.alice." + _session_id(auth_api, access)
    ) == _refresh_cookie(login)


async def test_refresh_without_cookie_is_rejected(make_client) -> None:
    client, _redis, _auth_api = await make_client()
    client.cookies.clear()

    with pytest.raises(jwt.DecodeError):
        await client.post("/auth/refresh-token")
