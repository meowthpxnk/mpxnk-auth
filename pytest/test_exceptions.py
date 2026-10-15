"""Unit tests for auth exception types."""

import pytest
from mpxnk_auth import AuthorizationError as PublicAuthorizationError
from mpxnk_auth.exceptions import (
    AuthorizationError,
    FailedRefreshSession,
    NotFoundSession,
    NotValidTokenType,
    SessionCacheStoreException,
    SessionException,
    SessionLimitReached,
)

pytestmark = pytest.mark.unit


def test_authorization_error_is_public() -> None:
    assert PublicAuthorizationError is AuthorizationError
    with pytest.raises(AuthorizationError):
        raise AuthorizationError("login failed")


def test_session_exception_includes_username_and_session() -> None:
    missing = SessionException("alice")
    found = NotFoundSession("alice", "sid")

    assert missing.session_id is None
    assert "alice" in str(missing)
    assert "None" in str(missing)
    assert isinstance(found, SessionCacheStoreException)
    assert found.session_id == "sid"
    assert "sid" in str(found)


def test_session_limit_records_how_many_to_revoke() -> None:
    err = SessionLimitReached("alice")
    err._set_session_count_to_revoke(2)

    assert err.session_count_to_revoke == 2
    assert isinstance(err, SessionException)


def test_refresh_and_token_type_errors_keep_session_ids() -> None:
    refresh = FailedRefreshSession("alice", "sid-1")
    wrong_type = NotValidTokenType("alice", "sid-2")

    assert refresh.session_id == "sid-1"
    assert wrong_type.session_id == "sid-2"
    assert isinstance(refresh, SessionException)
    assert isinstance(wrong_type, SessionException)
