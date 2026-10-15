"""Fixtures for mpxnk-auth unit and HTTP integration tests."""

import datetime
import fnmatch
from pathlib import Path

import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

import pytest
from mpxnk_auth import (
    AccessTokenResponseSchema,
    AuthAPI,
    JWTAuthSettings,
    UserBase,
)
from mpxnk_auth.fastapi.dependencies import (
    AuthAPIDepends,
    read_access_token,
)
from mpxnk_auth.fastapi.router import router as auth_router
from mpxnk_auth.hash_secret.hash_secret import (
    WrongSecret,
    hash_secret,
    verify_secret,
)


class UserSchema(UserBase):
    """App user carried inside access and refresh JWTs."""

    role: str


class UserLoginSchema(BaseModel):
    username: str
    password: str


class FakeRedis:
    """In-memory stand-in for the Redis commands CacheStore uses."""

    def __init__(self, *, decode_responses: bool = True) -> None:
        self.decode_responses = decode_responses
        self.store: dict[str, str] = {}
        self.expirations: dict[str, int | None] = {}

    @staticmethod
    def _name(key: str | bytes) -> str:
        if isinstance(key, bytes):
            return key.decode()
        return key

    def _value(self, value: str | None) -> str | bytes | None:
        if value is None or self.decode_responses:
            return value
        return value.encode()

    async def get(self, key: str | bytes) -> str | bytes | None:
        return self._value(self.store.get(self._name(key)))

    async def set(
        self,
        key: str | bytes,
        value: str,
        ex: int | None = None,
    ) -> None:
        name = self._name(key)
        self.store[name] = value
        self.expirations[name] = ex

    async def delete(self, *keys: str | bytes) -> None:
        for key in keys:
            name = self._name(key)
            self.store.pop(name, None)
            self.expirations.pop(name, None)

    async def keys(self, pattern: str | bytes) -> list[str | bytes]:
        matched = [
            key
            for key in self.store
            if fnmatch.fnmatch(key, self._name(pattern))
        ]
        if self.decode_responses:
            return matched
        return [key.encode() for key in matched]


def write_rsa_keys(keys_dir: Path) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_openssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    (keys_dir / "private.pem").write_bytes(private_pem)
    (keys_dir / "public.pem").write_bytes(public_openssh)


def auth_settings(
    keys_dir: Path,
    *,
    access_ttl: int = 900,
    refresh_ttl: int = 2_419_200,
    max_user_sessions: int = 5,
) -> JWTAuthSettings:
    return JWTAuthSettings(
        ACCESS_TOKEN_TTL=access_ttl,
        REFRESH_TOKEN_TTL=refresh_ttl,
        MAX_USER_SESSIONS=max_user_sessions,
        JWT_KEYS_PATH=str(keys_dir),
        JWT_ALGORITHM="RS256",
    )


def build_app(auth_api: AuthAPI, password_hash: str) -> FastAPI:
    """FastAPI app wired the way a consumer registers mpxnk-auth."""
    users = {
        "alice": {"password_hash": password_hash, "role": "user"},
        "bob": {"password_hash": password_hash, "role": "admin"},
    }
    application = FastAPI()
    application.state.auth_api = auth_api

    @application.post("/auth/login")
    async def login(
        user: UserLoginSchema,
        response: Response,
        api: AuthAPIDepends,
    ) -> AccessTokenResponseSchema:
        record = users.get(user.username)
        if record is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        try:
            verify_secret(user.password, record["password_hash"])
        except WrongSecret as exc:
            raise HTTPException(
                status_code=401, detail="Invalid credentials"
            ) from exc
        user_data = UserSchema(username=user.username, role=record["role"])
        return await api.issue_session(user_data, response)

    application.include_router(auth_router)

    closed = APIRouter(dependencies=[Depends(read_access_token)])

    @closed.get("/closed")
    async def closed_route() -> dict[str, bool]:
        return {"ok": True}

    application.include_router(closed)
    return application


@pytest.fixture(scope="session")
def rsa_keys_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    keys_dir = tmp_path_factory.mktemp("jwt_keys")
    write_rsa_keys(keys_dir)
    return keys_dir


@pytest.fixture
def foreign_keys_dir(tmp_path: Path) -> Path:
    keys_dir = tmp_path / "foreign"
    keys_dir.mkdir()
    write_rsa_keys(keys_dir)
    return keys_dir


@pytest.fixture(scope="session")
def password_hash() -> str:
    return hash_secret("secret")


@pytest.fixture
def fake_redis_cls() -> type[FakeRedis]:
    return FakeRedis


@pytest.fixture
def make_auth_api(rsa_keys_dir: Path):
    def _make(
        redis: FakeRedis | None = None,
        *,
        keys_dir: Path | None = None,
        access_ttl: int = 900,
        refresh_ttl: int = 2_419_200,
        max_user_sessions: int = 5,
    ) -> tuple[AuthAPI, FakeRedis]:
        client = redis if redis is not None else FakeRedis()
        api = AuthAPI(
            client,
            UserSchema,
            auth_settings(
                keys_dir or rsa_keys_dir,
                access_ttl=access_ttl,
                refresh_ttl=refresh_ttl,
                max_user_sessions=max_user_sessions,
            ),
        )
        return api, client

    return _make


@pytest.fixture
def auth_api(make_auth_api) -> AuthAPI:
    api, _redis = make_auth_api()
    return api


@pytest_asyncio.fixture
async def make_client(rsa_keys_dir: Path, password_hash: str):
    opened: list[AsyncClient] = []

    async def _make(
        *,
        access_ttl: int = 900,
        refresh_ttl: int = 2_419_200,
        max_user_sessions: int = 5,
    ) -> tuple[AsyncClient, FakeRedis, AuthAPI]:
        redis = FakeRedis()
        api = AuthAPI(
            redis,
            UserSchema,
            auth_settings(
                rsa_keys_dir,
                access_ttl=access_ttl,
                refresh_ttl=refresh_ttl,
                max_user_sessions=max_user_sessions,
            ),
        )
        client = AsyncClient(
            transport=ASGITransport(app=build_app(api, password_hash)),
            base_url="http://test",
        )
        opened.append(client)
        return client, redis, api

    yield _make

    for client in opened:
        await client.aclose()


@pytest.fixture
def token_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Move JWT time forward so two tokens issued back to back differ."""
    state = {"now": datetime.datetime.now(datetime.UTC)}

    def _now() -> datetime.datetime:
        current = state["now"]
        state["now"] = current + datetime.timedelta(days=1)
        return current

    monkeypatch.setattr(
        "mpxnk_auth.auth_api.jwt_provider.get_now_time",
        _now,
    )
