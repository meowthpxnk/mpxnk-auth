SESSIONS_F: str = "userSession.{USERNAME}."
CURRENT_SESSION_F: str = SESSIONS_F + "{SESSION_UUID}"
RESERVED_USER_FIELDS = frozenset({"session_id", "exp", "type"})
REFRESH_TOKEN_COOKIE: str = "Refresh-Token"
