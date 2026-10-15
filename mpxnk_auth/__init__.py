"""JWT RS256 session auth for FastAPI with Redis-backed refresh tokens."""

from .auth_api import AuthAPI
from .exceptions import AuthorizationError, NotFoundSession
from .schemas import (
    AccessTokenResponseSchema,
    UserBase,
)
from .settings import JWTAuthSettings

__version__ = "1.0.1"

__all__ = [
    "AccessTokenResponseSchema",
    "AuthAPI",
    "AuthorizationError",
    "JWTAuthSettings",
    "NotFoundSession",
    "UserBase",
    "__version__",
]
