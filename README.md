# Meowthpxnk multisession auth util for FastAPI

- [How this works](#how-this-works)
- [Settings](#settings)
- [JWT keys](#jwt-keys)
- [How install multisession](#how-install-multisession)
- [API](#api)

## How this works

Multisession auth. One account is one `username`. Each successful login opens a separate session for that username: its own `session_id`, its own access JWT, and its own refresh JWT.

The access token is returned in the JSON body and sent as `Authorization: Bearer`. The refresh token is stored in Redis at `userSession.{username}.{session_id}` and set as the `HttpOnly` cookie `Refresh-Token`. Protected routes decode the access JWT and then check that this Redis key still exists. They do not read the database. The access JWT itself is not stored.

### Session cap

A username may hold **5 live sessions** (`MAX_USER_SESSIONS`). The cap is counted from Redis keys `userSession.{username}.`\*.

The 6th login still opens, then the oldest session is deleted. Oldest means the smallest refresh `exp`. A refresh rewrites `exp`, so a session that was just refreshed is newer than one that has been idle. Logout removes only the current key. `revoke-all-sessions` removes every key of that username. Once a key is gone, that session's access token fails on the next request.

### Refresh

`POST /auth/refresh-token` reads the `Refresh-Token` cookie and keeps the same `session_id`.

1. The JWT must be a valid refresh token.
2. Redis must still hold `userSession.{username}.{session_id}`. A missing key fails the refresh and leaves the user's other sessions in place.
3. The cookie string must equal the value stored for that session. A different string revokes every session of that username.
4. On a match, a new access token and a new refresh token are issued. Redis and the cookie are overwritten. The previous refresh token is dead.

Default lifetimes: access **15 minutes** (`ACCESS_TOKEN_TTL=900`), refresh **28 days** (`REFRESH_TOKEN_TTL=2419200`).

### Security

An access token is valid only while its Redis session key exists and `exp` has not passed. Logout, `revoke-all-sessions`, `revoke-all-sessions-except-current`, session-cap eviction, and a reused refresh token delete that key, so the access JWT returns `401` on the next request even if `exp` is still in the future. Until one of those happens, a stolen access token works for at most 15 minutes.

The refresh token is the long-lived secret, so it rotates. The first use matches Redis and replaces the token. A second use of the same token, while the session key is still there, no longer matches, and every session of that `username` is deleted, including the one just created. The account is not banned. A password login opens a new session. Whoever still holds the old cookie is the side that triggers the wipe. If the session key is already gone, the refresh fails and the other sessions stay.

## Settings

`AuthAPI` takes a Redis client, your user class, and optional `JWTAuthSettings`. With no settings object, values come from the environment.

```py
from mpxnk_auth import AuthAPI, JWTAuthSettings

auth_api = AuthAPI(
    redis_client,
    UserSchema,
    JWTAuthSettings(
        ACCESS_TOKEN_TTL=900,
        REFRESH_TOKEN_TTL=2419200,
        MAX_USER_SESSIONS=5,
        JWT_KEYS_PATH="jwt_keys",
        JWT_ALGORITHM="RS256",
    ),
)
api.state.auth_api = auth_api
```

| Env                 | Default    | What it sets                                                    |
| ------------------- | ---------- | --------------------------------------------------------------- |
| `ACCESS_TOKEN_TTL`  | `900`      | Access JWT lifetime, seconds (15 minutes)                       |
| `REFRESH_TOKEN_TTL` | `2419200`  | Refresh JWT, Redis key, and cookie `Max-Age`, seconds (28 days) |
| `MAX_USER_SESSIONS` | `5`        | Live sessions per `username`                                    |
| `JWT_KEYS_PATH`     | `jwt_keys` | Directory with the RSA key files                                |
| `JWT_ALGORITHM`     | `RS256`    | JWT algorithm. Key files are RSA                                |

Pass those env names into `JWTAuthSettings(...)`. Field names such as `access_ttl` are not accepted.

## JWT keys

`AuthAPI` reads the key pair from `JWT_KEYS_PATH` (default `jwt_keys`) when it is created.

Generate an unencrypted PEM private key, then the OpenSSH public key. `public.pem` must be `ssh-rsa ...`, not a PEM `BEGIN PUBLIC KEY` block.

```sh
mkdir jwt_keys
openssl genpkey -algorithm RSA -out jwt_keys/private.pem -pkeyopt rsa_keygen_bits:2048
ssh-keygen -y -f jwt_keys/private.pem > jwt_keys/public.pem
```

Register the directory with `JWT_KEYS_PATH`, or pass it into settings. The file names stay `private.pem` and `public.pem`.

```py
auth_api = AuthAPI(
    redis_client,
    UserSchema,
    JWTAuthSettings(JWT_KEYS_PATH="jwt_keys"),
)
```

## How install multisession

1. Install library

```sh
pip install mpxnk-auth
```

```sh
poetry add mpxnk-auth
```

1. Generate and register JWT keys. See [JWT keys](#jwt-keys).
2. Create environment: `redis-client`, `fastapi`

- `redis-client`

```py
from redis.asyncio import Redis as AsyncRedis

from . import settings

redis_client = AsyncRedis.from_url(str(settings.redis.uri))
```

- `fastapi`

```py
api = FastAPI()
config = Config(
    self.api,
    settings.host,
    settings.port,
    log_config=log_config,
)
server = Server(config)
```

1. Setup `auth_api` to API state.

```py
api.state.auth_api = auth_api
```

1. Create UserSchema with `pydantic` `BaseModel`
   You can pass any fields to `UserSchema` such as EnumRole or any status, if you need to send this fields to any source.

```python
from mpxnk_auth import UserBase

class UserSchema(UserBase):
    username: str
    role: UserRoleEnum
    email: str
```

1. Create UserLogin schema for `/login` route

```py
class UserLoginSchema(BaseModel):
    username: str
    password: str
```

1. Create authorisation function

- `auth-func`

Import hash functions

```py
from mpxnk_auth.hash_secret.hash_secret import hash_secret, verify_secret
```

And realize authorize function

```py
async def authorize(user: UserLoginSchema) -> UserSchema:
    user_db = await get_user_by_username(user.username)
    verify_secret(user.password, user_db.password_hash)

    user_data = UserSchema(
        username=user_db.username,
    )
    return user_data
```

1. Regisrate login route with authorisation function

```py
from fastapi import HTTPException, Response

from mpxnk_auth import AccessTokenResponseSchema
from mpxnk_auth.fastapi.router import router
from mpxnk_auth.fastapi.dependencies import AuthAPIDepends

from app.exceptions import AppException
from app.schemas import UserLoginSchema
from app.services import UserService # User CRUD service

from app.api.dependencies import DatabaseDepends # ORM SQL dependency


@router.post("/login")
async def login(
    db: DatabaseDepends,
    user: UserLoginSchema,
    response: Response,
    auth_api: AuthAPIDepends,
) -> AccessTokenResponseSchema:
    try:
        user_data = await UserService(db).authorize(user)
    except AppException as e:
        raise HTTPException(status_code=401, detail=str(e)) from e
    return await auth_api.issue_session(user_data, response)
```

1. Setup router to your internal router
   You need to create two routers, and routes which need authorisation require `read_access_token` dependency.

```py
from fastapi import APIRouter, Depends
from mpxnk_auth.fastapi.dependencies import read_access_token

from . import auth_routes, closed_routes, home_routes, main_routes

router = APIRouter()
router_internal = APIRouter(dependencies=[Depends(read_access_token)])

router_internal.include_router(closed_routes.router)
router_internal.include_router(home_routes.router)
router_internal.include_router(main_routes.router)

router.include_router(auth_routes.router)
router.include_router(router_internal)
```

## API

Routes from `mpxnk_auth.fastapi.router`. No JSON body. Bearer routes use `Authorization: Bearer <access_token>`. A bad JWT, the wrong token type, or a session key that is no longer in Redis returns `401` `{ "detail": "Invalid token" }`.

### `POST /auth/refresh-token`

Rotates the session and keeps the same `session_id`.

**Request** — cookie `Refresh-Token: <refresh jwt>`

**Response** `200` — `AccessTokenResponseSchema`, plus `Set-Cookie: Refresh-Token` (`HttpOnly`, `Secure`, `SameSite=None`, `Max-Age` = refresh TTL)

```json
{ "access_token": "<jwt>" }
```

A cookie whose session key is missing fails the refresh and leaves other sessions in place. A cookie that finds the key but does not match the stored refresh token revokes every session of that user.

### `GET /auth/me`

**Request** — `Authorization: Bearer <access_token>`

**Response** `200` — your `UserSchema`

```json
{ "username": "alice", "role": "user", "email": "alice@example.com" }
```

### `POST /auth/logout`

Revokes the session from the access token.

**Request** — `Authorization: Bearer <access_token>`

**Response** `200` empty. After that, the same access token returns `401`. A request whose session is already gone also returns `401`.

### `POST /auth/revoke-all-sessions`

Revokes every session of the user, including the current one.

**Request** — `Authorization: Bearer <access_token>`

**Response** `200` empty

### `POST /auth/revoke-all-sessions-except-current`

Revokes every session except the current one.

**Request** — `Authorization: Bearer <access_token>`

**Response** `200` empty

### `POST /auth/login`

Registered by the app. See step 8.

---

$XOXO$
_meowthpxnk_
..
