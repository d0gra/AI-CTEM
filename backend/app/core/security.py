"""Password hashing, opaque tokens, TOTP and credential encryption."""

import base64
import hashlib
import hmac
import secrets

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import get_settings

_hasher = PasswordHasher()  # argon2-cffi defaults to Argon2id with RFC 9106 low-memory profile


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# A fixed hash used to equalise timing when the account does not exist.
DUMMY_HASH = _hasher.hash("timing-equalisation-placeholder")


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Tokens are high entropy, so a keyed SHA-256 is sufficient for storage."""
    key = get_settings().secret_key.encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="CTEM Platform")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)


def _fernet() -> MultiFernet:
    settings = get_settings()
    keys = [k.strip() for k in settings.encryption_keys.split(",") if k.strip()]
    if not keys:
        if settings.is_production:
            raise RuntimeError("CTEM_ENCRYPTION_KEYS is not configured")
        # Deterministic development key derived from the dev secret; never used in production.
        keys = [base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest()).decode()]
    return MultiFernet([Fernet(k) for k in keys])


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Stored secret cannot be decrypted with the configured keys") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
