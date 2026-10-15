"""Unit tests for token, key, and cookie helpers."""

import datetime
import uuid
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from fastapi import Response

import pytest
from mpxnk_auth.constants import REFRESH_TOKEN_COOKIE
from mpxnk_auth.schemas import UserBase
from mpxnk_auth.utils import (
    build_token_schemas,
    create_session_string_data,
    ensure_instance,
    ensure_subclass,
    gen_exp_time,
    get_now_time,
    load_rsa_key,
    set_refresh_token_cookie,
    validate_user_cls,
)

pytestmark = pytest.mark.unit


class UserSchema(UserBase):
    role: str


def test_get_now_time_is_utc() -> None:
    assert get_now_time().tzinfo is datetime.UTC


def test_gen_exp_time_adds_ttl_in_seconds() -> None:
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)

    assert gen_exp_time(900, now) == int(now.timestamp()) + 900


def test_ensure_instance_returns_matching_value() -> None:
    user = UserSchema(username="alice", role="user")

    assert ensure_instance(user, UserSchema, "user") is user


def test_ensure_instance_rejects_other_types() -> None:
    with pytest.raises(TypeError, match="user"):
        ensure_instance("alice", UserSchema, "user")


def test_ensure_subclass_rejects_instances_and_other_classes() -> None:
    with pytest.raises(TypeError, match="user_cls"):
        ensure_subclass(
            UserSchema(username="a", role="user"), UserBase, "user_cls"
        )
    with pytest.raises(TypeError, match="user_cls"):
        ensure_subclass(str, UserBase, "user_cls")


def test_validate_user_cls_accepts_extension() -> None:
    assert validate_user_cls(UserSchema) is UserSchema


def test_validate_user_cls_rejects_reserved_jwt_fields() -> None:
    class BadUser(UserBase):
        session_id: str

    with pytest.raises(TypeError, match="reserved JWT fields"):
        validate_user_cls(BadUser)


def test_validate_user_cls_requires_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fields = dict(UserSchema.model_fields)
    fields.pop("username")
    monkeypatch.setattr(UserSchema, "model_fields", fields)

    with pytest.raises(TypeError, match="username"):
        validate_user_cls(UserSchema)


def test_build_token_schemas_adds_jwt_claims() -> None:
    payload_cls, data_cls = build_token_schemas(UserSchema)

    assert issubclass(payload_cls, UserSchema)
    assert "session_id" in payload_cls.model_fields
    assert "exp" in data_cls.model_fields
    assert "type" in data_cls.model_fields
    assert "role" in data_cls.model_fields


def test_create_session_string_data_is_a_uuid() -> None:
    first = create_session_string_data()
    second = create_session_string_data()

    uuid.UUID(first)
    assert first != second


def test_set_refresh_token_cookie_flags() -> None:
    response = Response()

    set_refresh_token_cookie(response, "refresh-jwt", 120)

    header = response.headers["set-cookie"].casefold()
    assert header.startswith(f"{REFRESH_TOKEN_COOKIE}=refresh-jwt".casefold())
    assert "httponly" in header
    assert "secure" in header
    assert "samesite=none" in header
    assert "max-age=120" in header


def test_load_rsa_key_reads_pem_and_openssh(rsa_keys_dir: Path) -> None:
    private_key = load_rsa_key("private", str(rsa_keys_dir))
    public_key = load_rsa_key("public", str(rsa_keys_dir))

    assert isinstance(private_key, RSAPrivateKey)
    assert isinstance(public_key, RSAPublicKey)


def test_load_rsa_key_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_rsa_key("private", str(tmp_path))


def test_load_rsa_key_rejects_pem_public_key(tmp_path: Path) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / "public.pem").write_bytes(public_pem)

    with pytest.raises(UnsupportedAlgorithm):
        load_rsa_key("public", str(tmp_path))
