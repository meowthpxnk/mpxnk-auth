"""Unit tests for password hashing."""

import pytest
from mpxnk_auth.hash_secret.hash_secret import (
    WrongSecret,
    hash_secret,
    verify_secret,
)

pytestmark = pytest.mark.unit


def test_hash_secret_is_salted_hex_digest() -> None:
    first = hash_secret("secret")
    second = hash_secret("secret")

    assert first != second
    assert len(first) == 192
    int(first, 16)
    verify_secret("secret", first)
    verify_secret("secret", second)


def test_verify_secret_rejects_wrong_password() -> None:
    digest = hash_secret("secret")

    with pytest.raises(WrongSecret):
        verify_secret("other", digest)


def test_verify_secret_rejects_truncated_digest() -> None:
    with pytest.raises(WrongSecret):
        verify_secret("secret", "ab")


def test_unicode_secret_roundtrip() -> None:
    digest = hash_secret("п@роль")

    verify_secret("п@роль", digest)
    with pytest.raises(WrongSecret):
        verify_secret("пароль", digest)
