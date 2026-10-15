from typing import Literal, ParamSpec, TypeVar

P = ParamSpec("P")
T = TypeVar("T")

type TUsername = str
type TUserPassword = str
type TSessionId = str
type TRedisKey = str
type TRefreshToken = str
type TTokenTTL = int
type TKeyType = Literal["private", "public"]
type TTokenExpTime = int
type TSessionID = str
type TSessionRedisKey = str
