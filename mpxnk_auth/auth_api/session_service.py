from typing import Generic

from mpxnk_auth.exceptions import (
    FailedRefreshSession,
    NotFoundSession,
    NotValidTokenType,
    SessionLimitReached,
)
from mpxnk_auth.schemas import (
    DataT,
    JWTTokenTypeEnum,
    PayloadT,
    UserT,
)
from mpxnk_auth.settings import JWTAuthSettings
from mpxnk_auth.types import TUsername
from mpxnk_auth.utils import (
    create_session_string_data,
)

from .jwt_provider import AuthJWTProvider
from .session_cache_store import CacheStore, SessionCacheString


class AuthSessionService(Generic[UserT, PayloadT, DataT]):
    """Session lifecycle: issue, refresh, revoke, and decode access JWTs."""

    def __init__(
        self,
        settings: JWTAuthSettings | None,
        cache_store: CacheStore,
        jwt_provider: AuthJWTProvider,
        user_cls: type[UserT],
        token_payload_cls: type[PayloadT],
        token_data_cls: type[DataT],
    ):
        self.settings = settings
        self.cache_store = cache_store
        self.jwt_provider = jwt_provider
        self.user_cls = user_cls
        self.token_payload_cls = token_payload_cls
        self.token_data_cls = token_data_cls

    # -> SESSION LIFECYCLE

    async def create_session(self, data: UserT | PayloadT) -> tuple[str, str]:
        (
            session_data,
            access_token,
            refresh_token,
        ) = await self._generate_session_tokens(data)
        await self.cache_store.set_token(
            session_data,
            refresh_token,
            self.settings.refresh_ttl,
        )
        try:
            await self._validate_session_count(data.username)
        except SessionLimitReached as err:
            await self._revoke_last_sessions(
                session_data, err.session_count_to_revoke
            )

        return access_token, refresh_token

    async def revoke_session(self, session: SessionCacheString) -> None:
        await self.cache_store.remove_token(session)

    async def revoke_sessions(
        self, sessions: list[SessionCacheString]
    ) -> None:
        for session in sessions:
            await self.revoke_session(session)

    async def _revoke_last_sessions(
        self, session: SessionCacheString, count: int = 1
    ) -> None:
        """Evict the oldest session only when the user hit the cap."""
        previous_sessions = await self.cache_store.get_all_token_data(
            session.username
        )
        decoded = [
            await self._decode_refresh_token_data(token)
            for token in previous_sessions
        ]
        sessions_to_close = self._get_last_sessions(decoded, count)
        await self.revoke_sessions(sessions_to_close)

    async def revoke_all_sessions(
        self,
        username: TUsername,
        exclude_session_id: str | None = None,
    ) -> None:
        await self.cache_store.remove_all_tokens(username, exclude_session_id)

    async def refresh_session(self, refresh_token: str) -> tuple[str, str]:
        """Rotate a refresh token after Redis proves it is current."""
        data = await self._decode_refresh_token_data(refresh_token)
        try:
            await self._validate_refresh_token(data, refresh_token)
        except FailedRefreshSession:
            await self.revoke_all_sessions(data.username)
            raise
        return await self.create_session(data)

    # -> DECODING METHODS

    async def _decode_typed_token(
        self, token: str, expected_type: JWTTokenTypeEnum
    ) -> PayloadT:
        """Decode a JWT and reject the wrong token type."""
        data = self.jwt_provider.decode(token)
        self._validate_token_type(data, expected_type)
        await self._validate_session_id(data)
        return data

    async def decode_access_token(self, access_token: str) -> PayloadT | UserT:
        return await self._decode_typed_token(
            access_token, JWTTokenTypeEnum.ACCESS
        )

    async def _decode_refresh_token_data(self, refresh_token: str) -> PayloadT:
        return await self._decode_typed_token(
            refresh_token, JWTTokenTypeEnum.REFRESH
        )

    # -> LAST SESSION METHODS

    @staticmethod
    def _get_last_sessions(
        previous_sessions: list[PayloadT], count: int
    ) -> list[SessionCacheString]:
        """Pick the oldest session so it can be evicted first."""
        previous_sessions.sort(
            key=lambda session: session.exp
        )  # smallest exp = oldest
        sessions_to_close = previous_sessions[:count]

        return [
            SessionCacheString(session.username, session.session_id)
            for session in sessions_to_close
        ]

    # -> HELPER VALIDATION METHODS

    async def _validate_session_count(self, username: TUsername) -> None:
        """Raise when Redis session count is at or over the configured cap."""
        count_tokens = await self.cache_store.count_tokens(username)
        if count_tokens >= self.settings.max_user_sessions:
            err = SessionLimitReached(username)
            err._set_session_count_to_revoke(
                count_tokens - self.settings.max_user_sessions
            )
            raise err

    async def _validate_refresh_token(
        self, token_data: PayloadT, refresh_token_str: str
    ) -> None:
        """Block reused or stolen refresh tokens via the Redis value."""
        session_token = await self.cache_store.get_token(
            SessionCacheString(token_data.username, token_data.session_id)
        )
        if session_token != refresh_token_str:
            raise FailedRefreshSession(
                token_data.username, token_data.session_id
            )

    def _validate_token_type(
        self, token_data: PayloadT, expected_type: JWTTokenTypeEnum
    ) -> None:
        """Reject JWTs whose type does not match the expected kind."""
        if token_data.type != expected_type:
            raise NotValidTokenType(token_data.username, token_data.session_id)

    async def _validate_session_id(
        self,
        data: PayloadT,
    ) -> None:
        """Reject JWTs whose session_id does not match the expected kind."""
        exists = await self.cache_store.session_id_exists(
            data.username, data.session_id
        )
        if not exists:
            raise NotFoundSession(data.username, data.session_id)

    # -> MAIN TOKEN GENERATION

    async def _generate_session_tokens(
        self, data: UserT | PayloadT
    ) -> tuple[SessionCacheString, str, str]:
        """Keep session_id on refresh, or create a new one on login."""
        if isinstance(data, self.token_payload_cls):
            session_string = SessionCacheString(
                data.username, data.session_id
            )  # reuse id so refresh stays the same session
        elif isinstance(data, self.user_cls):
            session_string = SessionCacheString(
                data.username, create_session_string_data()
            )
        else:
            raise TypeError(
                f"Expected {self.user_cls.__name__} or token data, "
                f"got {type(data).__name__}"
            )

        payload = self.token_payload_cls.model_validate(
            {
                **data.model_dump(
                    exclude={"exp", "type", "session_id"}
                ),  # rebuild library claims
                "session_id": session_string.session_id,
            }
        )
        access_token, refresh_token = self.jwt_provider.encode(payload)
        return session_string, access_token, refresh_token

    # -> UTILS
    def payload_to_userdata(self, payload: PayloadT) -> UserT:
        return self.user_cls.model_validate(payload.model_dump())
