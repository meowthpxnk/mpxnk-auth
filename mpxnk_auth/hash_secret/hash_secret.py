import binascii
import hashlib
import os


class WrongSecret(Exception):
    pass


def hash_secret(secret: str) -> str:
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii")

    secret_hash = hashlib.pbkdf2_hmac(
        "sha512", secret.encode("utf-8"), salt, 100000
    )

    secret_hash = binascii.hexlify(secret_hash)

    return (salt + secret_hash).decode("ascii")


def verify_secret(secret: str, secret_hash: str) -> None:
    salt = secret_hash[:64]
    secret_hash = secret_hash[64:]

    current_secret_hash = hashlib.pbkdf2_hmac(
        "sha512", secret.encode("utf-8"), salt.encode("ascii"), 100000
    )

    current_secret_hash = binascii.hexlify(current_secret_hash).decode("ascii")

    if not current_secret_hash == secret_hash:
        raise WrongSecret
