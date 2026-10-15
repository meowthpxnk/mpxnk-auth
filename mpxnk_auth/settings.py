from pydantic import Field
from pydantic_settings import BaseSettings


class JWTAuthSettings(BaseSettings):
    """JWT TTLs, session cap, and key path loaded from env aliases."""

    access_ttl: int = Field(
        900,
        alias="ACCESS_TOKEN_TTL",
    )
    refresh_ttl: int = Field(
        2419200,
        alias="REFRESH_TOKEN_TTL",
    )
    max_user_sessions: int = Field(
        5,
        alias="MAX_USER_SESSIONS",
    )
    keys_path: str = Field(
        "jwt_keys",
        alias="JWT_KEYS_PATH",
    )
    algorithm: str = Field(
        "RS256",
        alias="JWT_ALGORITHM",
    )
