import datetime
import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from fastapi import Response

from .constants import REFRESH_TOKEN_COOKIE, RESERVED_USER_FIELDS
from .schemas import (
    RSAKeyConfig,
    TokenDataBase,
    TokenPayloadBase,
    UserBase,
)
from .types import T, TKeyType, TSessionID, TTokenTTL

# --> DATETIME METHODS


def get_now_time() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def gen_exp_time(ttl: int, now: datetime.datetime) -> int:
    return int((now + datetime.timedelta(seconds=ttl)).timestamp())


# --> INSTANCES METHODS


def ensure_instance(value: object, expected: type[T], name: str) -> T:
    """Fail when a value is not an instance of the expected class."""
    if not isinstance(value, expected):
        raise TypeError(
            f"{name} must be an instance of {expected.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


def ensure_subclass(value: type, expected: type[T], name: str) -> type[T]:
    """Fail when a class does not subclass the expected base."""
    if not isinstance(value, type) or not issubclass(value, expected):
        label = getattr(value, "__name__", repr(value))
        raise TypeError(
            f"{name} must subclass {expected.__name__}, got {label}"
        )
    return value


# --> TOKEN SCHEMAS METHODS


def validate_user_cls(user_cls: type[UserBase]) -> type[UserBase]:
    """Reject user models that miss username or collide with JWT fields."""
    ensure_subclass(user_cls, UserBase, "user_cls")
    if "username" not in user_cls.model_fields:
        raise TypeError(f"{user_cls.__name__} must define a 'username' field")

    clash = RESERVED_USER_FIELDS.intersection(user_cls.model_fields)
    if clash:
        raise TypeError(
            f"{user_cls.__name__} cannot define reserved JWT fields: "
            f"{', '.join(sorted(clash))}"
        )
    return user_cls


def build_token_schemas(
    user_cls: type[UserBase],
) -> tuple[type[TokenPayloadBase], type[TokenDataBase]]:
    """Build payload/data Pydantic models from the app User class."""
    validate_user_cls(user_cls)

    class TokenPayloadSchema(user_cls, TokenPayloadBase):
        pass

    class TokenDataSchema(TokenPayloadSchema, TokenDataBase):
        pass

    return TokenPayloadSchema, TokenDataSchema


# --> RSA KEYS METHODS

RSA_KEY_MAP: dict[TKeyType, RSAKeyConfig] = {
    "private": {
        "name": "private",
        "class": RSAPrivateKey,
        "serializer": serialization.load_pem_private_key,
        "kwargs": {"password": None},
    },
    "public": {
        "name": "public",
        "class": RSAPublicKey,
        "serializer": serialization.load_ssh_public_key,
        "kwargs": {},
    },
}


def load_rsa_key(key_type: TKeyType, keys_path: str) -> bytes:
    KEY = RSA_KEY_MAP[key_type]

    # Extract key configuration
    name, key_cls, serializer, kwargs = (
        KEY["name"],
        KEY["class"],
        KEY["serializer"],
        KEY["kwargs"],
    )

    # Load key from file
    key_path = os.path.join(keys_path, f"{name}.pem")
    with open(key_path, "rb") as f:
        key = f.read()

    # Convert key to bytes
    key_bytes = key.encode() if isinstance(key, str) else key

    # Deserialize key
    loaded_key = serializer(
        key_bytes,
        **kwargs,
    )

    if not isinstance(loaded_key, key_cls):
        raise TypeError(f"{key_type} key is not an RSA key")
    return loaded_key


# --> SESSION STRING DATA METHODS


def create_session_string_data() -> TSessionID:
    return str(uuid.uuid4())


# --> REFRESH TOKEN COOKIE METHODS


def set_refresh_token_cookie(
    response: Response,
    refresh_token: str,
    refresh_ttl: TTokenTTL,
) -> None:
    response.set_cookie(
        REFRESH_TOKEN_COOKIE,
        refresh_token,
        max_age=refresh_ttl,
        httponly=True,
        secure=True,
        samesite="None",
    )
