from typing import Generic

import redis.asyncio as aioredis
from fastapi import Response

from mpxnk_auth.schemas import AccessTokenResponseSchema, UserT
from mpxnk_auth.settings import JWTAuthSettings
from mpxnk_auth.utils import build_token_schemas, set_refresh_token_cookie

from .jwt_provider import AuthJWTProvider
from .session_cache_store import CacheStore
from .session_service import AuthSessionService


class AuthAPI(Generic[UserT]):
    """FastAPI auth facade: session routes, JWT dependencies, session issue."""

    def __init__(
        self,
        redis_client: aioredis.Redis,
        user_cls: type[UserT],
        settings: JWTAuthSettings | None = None,
        *,
        tags: list[str] | None = None,
    ) -> None:
        self.settings = settings or JWTAuthSettings()
        self.user_cls = user_cls
        self.tags = tags or ["auth"]
        self.payload_cls, self.data_cls = build_token_schemas(user_cls)
        self.cache_store = CacheStore(redis_client)
        self.jwt_provider = AuthJWTProvider(
            self.settings,
            self.payload_cls,
            self.data_cls,
        )

        self.session_service = AuthSessionService(
            self.settings,
            self.cache_store,
            self.jwt_provider,
            self.user_cls,
            self.payload_cls,
            self.data_cls,
        )

    async def issue_session(
        self,
        user: UserT,
        response: Response,
    ) -> AccessTokenResponseSchema:
        (
            access_token,
            refresh_token,
        ) = await self.session_service.create_session(user)
        set_refresh_token_cookie(
            response,
            refresh_token,
            self.settings.refresh_ttl,
        )
        return AccessTokenResponseSchema(access_token=access_token)
