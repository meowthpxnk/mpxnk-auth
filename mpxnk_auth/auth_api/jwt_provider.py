import datetime
from dataclasses import dataclass
from typing import Generic

import jwt

from mpxnk_auth.schemas import DataT, JWTTokenTypeEnum, PayloadT
from mpxnk_auth.settings import JWTAuthSettings
from mpxnk_auth.utils import (
    ensure_instance,
    gen_exp_time,
    get_now_time,
    load_rsa_key,
)

# --> RSA KEYS DATACLASS


@dataclass
class RSAKeys:
    private_key: bytes
    public_key: bytes

    @classmethod
    def from_pem(
        cls,
        keys_path: str,
    ) -> "RSAKeys":
        """Load RSA keys from PEM files."""

        return cls(
            private_key=load_rsa_key("private", keys_path),
            public_key=load_rsa_key("public", keys_path),
        )


# --> AUTH JWT PROVIDER CLASS


class AuthJWTProvider(Generic[PayloadT, DataT]):
    """RS256 encode/decode of access and refresh JWTs."""

    __rsa_keys: RSAKeys

    # -> INIT METHODS

    def __init__(
        self,
        settings: JWTAuthSettings,
        token_payload_cls: type[PayloadT],
        token_data_cls: type[DataT],
    ) -> None:
        self.settings = settings
        self.token_payload_cls = token_payload_cls
        self.token_data_cls = token_data_cls
        self.__rsa_keys = RSAKeys.from_pem(self.settings.keys_path)

    # -> HELPING METHODS

    def _gen_payload(
        self,
        payload: PayloadT,
        token_type: JWTTokenTypeEnum,
        ttl: int,
        now: datetime.datetime,
    ) -> DataT:
        """Copy user claims and stamp type plus unix exp."""
        return self.token_data_cls.model_validate(
            {
                **payload.model_dump(),
                "type": token_type,
                "exp": gen_exp_time(ttl, now),
            }
        )

    def _encode_token(self, payload: DataT) -> str:
        return jwt.encode(
            payload.model_dump(
                mode="json"
            ),  # enums must be JSON values for PyJWT
            key=self.__rsa_keys.private_key,
            algorithm=self.settings.algorithm,
        )

    # -> JWT ENCODE/DECODE METHODS

    def encode(self, payload: PayloadT) -> tuple[str, str]:
        """Issue a matching access+refresh pair from one payload."""
        payload = ensure_instance(payload, self.token_payload_cls, "payload")
        now = get_now_time()

        def gen_tkn(token_type: JWTTokenTypeEnum, ttl: int) -> str:
            return self._encode_token(
                self._gen_payload(payload, token_type, ttl, now)
            )

        access_token = gen_tkn(
            JWTTokenTypeEnum.ACCESS, self.settings.access_ttl
        )
        refresh_token = gen_tkn(
            JWTTokenTypeEnum.REFRESH, self.settings.refresh_ttl
        )

        return access_token, refresh_token

    def decode(self, token: str) -> DataT:
        data = jwt.decode(
            token,
            self.__rsa_keys.public_key,
            algorithms=[self.settings.algorithm],
        )
        return self.token_data_cls.model_validate(data)
