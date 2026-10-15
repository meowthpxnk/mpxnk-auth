from fastapi import APIRouter, HTTPException, Response

from mpxnk_auth.auth_api.session_cache_store import SessionCacheString
from mpxnk_auth.exceptions import NotFoundSession
from mpxnk_auth.schemas import AccessTokenResponseSchema, UserT
from mpxnk_auth.utils import set_refresh_token_cookie

from .dependencies import (
    GetPayloadDataDepends,
    GetUserDataDepends,
    RefreshTokenDepends,
    SessionServiceDepends,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/refresh-token")
async def refresh_token(
    session_service: SessionServiceDepends,
    response: Response,
    req_refresh_token: RefreshTokenDepends,
) -> AccessTokenResponseSchema:
    access_token, refresh = await session_service.refresh_session(
        req_refresh_token
    )
    set_refresh_token_cookie(
        response, refresh, session_service.settings.refresh_ttl
    )
    return AccessTokenResponseSchema(access_token=access_token)


@router.get("/me")
async def me(data: GetUserDataDepends) -> UserT:
    return data


@router.post("/logout")
async def logout(
    session_service: SessionServiceDepends,
    data: GetPayloadDataDepends,
) -> None:
    try:
        await session_service.revoke_session(
            SessionCacheString(data.username, data.session_id)
        )
    except NotFoundSession as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/revoke-all-sessions")
async def revoke_all_sessions(
    data: GetPayloadDataDepends,
    session_service: SessionServiceDepends,
) -> None:
    await session_service.revoke_all_sessions(data.username)


@router.post("/revoke-all-sessions-except-current")
async def revoke_all_sessions_except_current(
    data: GetPayloadDataDepends,
    session_service: SessionServiceDepends,
) -> None:
    await session_service.revoke_all_sessions(
        data.username, exclude_session_id=data.session_id
    )
