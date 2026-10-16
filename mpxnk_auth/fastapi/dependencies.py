from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from mpxnk_auth.auth_api.session_service import AuthSessionService
from mpxnk_auth.constants import REFRESH_TOKEN_COOKIE
from mpxnk_auth.schemas import PayloadT, UserT

if TYPE_CHECKING:
    from mpxnk_auth.auth_api import AuthAPI


# -> Auth API Service Dependency


def get_auth_api(request: Request) -> "AuthAPI":
    return request.app.state.auth_api


AuthAPIDepends = Annotated[
    "AuthAPI",
    Depends(get_auth_api),
]


# -> Session Service Dependency


def get_session_service(auth_api: AuthAPIDepends) -> AuthSessionService:
    return auth_api.session_service


SessionServiceDepends = Annotated[
    AuthSessionService,
    Depends(get_session_service),
]

# -> Refresh Token Dependency


def get_refresh_token(request: Request) -> str | None:
    return request.cookies.get(REFRESH_TOKEN_COOKIE)


RefreshTokenDepends = Annotated[
    str | None,
    Depends(get_refresh_token),
]

# -> Bearer Auth Dependency

bearer = HTTPBearer()

BearerCredentialsDepends = Annotated[
    HTTPAuthorizationCredentials,
    Depends(bearer),
]
# -> Access Token Dependency


async def get_current_token(
    credentials: BearerCredentialsDepends,
) -> str:
    return credentials.credentials


BearerAuthDepends = Annotated[
    str,
    Depends(get_current_token),
]

# -> Read Access Token Dependency


async def read_access_token(
    service: SessionServiceDepends,
    bearer_token: BearerAuthDepends,
) -> PayloadT | UserT:
    try:
        return await service.decode_access_token(bearer_token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


GetPayloadDataDepends = Annotated[
    PayloadT,
    Depends(read_access_token),
]

# -> Get User Dependency


def get_user(
    service: SessionServiceDepends,
    payload: GetPayloadDataDepends,
) -> UserT:
    return service.payload_to_userdata(payload)


GetUserDataDepends = Annotated[
    UserT,
    Depends(get_user),
]
