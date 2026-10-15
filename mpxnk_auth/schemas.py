import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import BaseModel
from typing_extensions import TypedDict

from .types import TSessionID, TTokenExpTime, TUsername

# --> HELPING TYPES


RSAKeyConfig = TypedDict(
    "RSAKeyConfig",
    {
        "name": str,
        "class": type,
        "serializer": Callable[..., Any],
        "kwargs": dict[str, Any],
    },
)


# --> HELPING DATA CLASSES


@dataclass
class SessionStringData:
    username: TUsername
    session_id: TSessionID


# --> ENUMS


class JWTTokenTypeEnum(enum.Enum):
    """Marks a JWT as access or refresh."""

    ACCESS = "ACCESS"
    REFRESH = "REFRESH"


# --> PYDANTIC SCHEMAS


class UserBase(BaseModel):
    """User contract the app must extend: username plus extra claims."""

    username: TUsername


class TokenPayloadBase(UserBase):
    """JWT claims written into a token before expiry and type are added."""

    session_id: TSessionID


class TokenDataBase(TokenPayloadBase):
    """Fully decoded JWT: user claims, session, expiry, and token type."""

    exp: TTokenExpTime
    type: JWTTokenTypeEnum


class AccessTokenResponseSchema(BaseModel):
    """Schema for the access token response."""

    access_token: str


# --> SCHEMAS TYPES


UserT = TypeVar("UserT", bound=UserBase)
PayloadT = TypeVar("PayloadT", bound=TokenPayloadBase)
DataT = TypeVar("DataT", bound=TokenDataBase)
