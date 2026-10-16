from collections.abc import Awaitable, Callable
from functools import wraps

import redis.asyncio as aioredis

from mpxnk_auth.constants import CURRENT_SESSION_F, SESSIONS_F
from mpxnk_auth.exceptions import NotFoundSession
from mpxnk_auth.schemas import SessionStringData, TSessionID
from mpxnk_auth.types import (
    P,
    T,
    TRefreshToken,
    TSessionRedisKey,
    TTokenTTL,
    TUsername,
)

# --> SESSION CACHE HELPER CLASS


class SessionCacheString(SessionStringData):
    """Redis key patterns for one user session or all sessions of a user."""

    @property
    def key(self) -> TSessionRedisKey:
        return CURRENT_SESSION_F.format(
            USERNAME=self.username, SESSION_UUID=self.session_id
        )

    @classmethod
    def get_all_keys(cls, username: TUsername) -> list[TSessionRedisKey]:
        return SESSIONS_F.format(USERNAME=username) + "*"


# --> SESSION CACHE STORE CLASS


class CacheStore:
    """Store, read, and delete refresh tokens in Redis."""

    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client

    # -> HELPER METHODS

    @staticmethod
    def required_token_exists(
        func: Callable[P, Awaitable[T]],
    ) -> Callable[P, Awaitable[T]]:
        """
        Decorator to check if the token exists before calling the function.
        If the token does not exist, raise a NotFoundSession error.
        """

        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            self: CacheStore = args[0]
            session: SessionCacheString = args[1]
            await self.get_token(session)
            return await func(*args, **kwargs)

        return wrapper

    @staticmethod
    def _as_str(value: bytes | str) -> str:
        """Normalize Redis bytes-or-str values to str."""
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return value

    # -> SESSION CACHE STORE METHODS

    async def get_token(self, session: SessionCacheString) -> str:
        token = await self.redis.get(session.key)
        if token is None:
            raise NotFoundSession(session.username, session.session_id)
        return self._as_str(token)

    async def set_token(
        self,
        session: SessionCacheString,
        refresh_token: TRefreshToken,
        refresh_ttl: TTokenTTL,
    ) -> None:
        await self.redis.set(
            session.key,
            refresh_token,
            refresh_ttl,
        )

    @required_token_exists
    async def remove_token(self, session: SessionCacheString) -> None:
        await self.redis.delete(session.key)

    async def remove_all_tokens(
        self, username: TUsername, exclude_session_id: str | None = None
    ) -> None:
        keys = await self.get_all_token_names(username)

        # Filter out the session to exclude from the keys
        if exclude_session_id:
            exclude_session = SessionCacheString(username, exclude_session_id)
            keys = list(
                filter(
                    lambda key: self._as_str(key) != exclude_session.key, keys
                )
            )

        for key in keys:
            await self.redis.delete(key)

        await self.redis.delete(SessionCacheString.get_all_keys(username))

    # -> ALL TOKENS GETTERS

    async def get_all_token_data(self, username: TUsername) -> list[str]:
        tokens = await self.get_all_token_names(username)
        return [await self.redis.get(token) for token in tokens]

    async def get_all_token_names(self, username: TUsername) -> list[str]:
        return await self.redis.keys(SessionCacheString.get_all_keys(username))

    async def count_tokens(self, username: TUsername) -> int:
        return len(await self.get_all_token_names(username))

    async def session_id_exists(
        self, username: TUsername, session_id: TSessionID
    ) -> bool:
        exists = await self.redis.get(
            SessionCacheString(username, session_id).key
        )
        return bool(exists)
