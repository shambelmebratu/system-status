"""Transparent at-rest encryption for stored secrets (agent/bot tokens, webhook URLs)."""
import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from .config import get_settings

PREFIX = "enc:v1:"


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    key = settings.encryption_key.strip()
    if key:
        try:
            return Fernet(key.encode())  # a proper generated Fernet key is used as-is
        except ValueError:
            pass  # any other non-empty value is treated as a passphrase
    source = key or settings.jwt_secret
    # NOTE: this salt predates the SM-Watch rename and must never change: it derives the key that decrypts stored secrets.
    derived = hashlib.sha256(b"northstar-secrets:" + source.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(value: str) -> str:
    return PREFIX + _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    if not value.startswith(PREFIX):
        return value  # legacy plaintext row, re-encrypted on next write / by migration 0009
    try:
        return _fernet().decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken as error:
        raise ValueError("Cannot decrypt stored secret: ENCRYPTION_KEY/JWT_SECRET changed") from error


class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return encrypt(value) if value else value

    def process_result_value(self, value, dialect):
        return decrypt(value) if value else value
