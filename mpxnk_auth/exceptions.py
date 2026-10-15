from __future__ import annotations

from .types import TSessionID, TUsername


class SessionException(Exception):
    """Session errors that carry username and optional session id."""

    def __init__(
        self,
        username: TUsername,
        session_id: TSessionID | None = None,
    ) -> None:
        self.username = username
        self.session_id = session_id
        super().__init__(
            "Session exception for username: "
            f"{username} and session_id: "
            f"{session_id if session_id else 'None'}"
        )


# --> SESSION CACHE STORE EXCEPTIONS


class SessionCacheStoreException(SessionException):
    """Session cache store errors."""


class NotFoundSession(SessionCacheStoreException):
    """Redis session key that does not exist."""


# --> OTHER SESSION EXCEPTIONS


class SessionLimitReached(SessionException):
    session_count_to_revoke: int

    """No eviction needed: the user is under the session cap."""

    def _set_session_count_to_revoke(
        self, session_count_to_revoke: int
    ) -> None:
        self.session_count_to_revoke = session_count_to_revoke


class FailedRefreshSession(SessionException):
    """Refresh token does not match the Redis session value."""


class NotValidTokenType(SessionException):
    """JWT used with the wrong type (access vs refresh)."""


class AuthorizationError(Exception):
    """Login authorize callback failed."""
