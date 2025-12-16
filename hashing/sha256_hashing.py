import hashlib
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordSHA256Hash:
    hash: str
    salt: str


class PasswordSHA256Hasher:
    """
    Password hasher using SHA-256 with per-password salt
    """
    SALT_BYTES = 16  # 128-bit salt

    @staticmethod
    def hash_password(password: str) -> PasswordSHA256Hash:
        if len(password) < 1:
            raise ValueError("Password must be not empty")
        salt = secrets.token_hex(PasswordSHA256Hasher.SALT_BYTES)
        hash_value = PasswordSHA256Hasher._sha256(password, salt)
        return PasswordSHA256Hash(hash=hash_value, salt=salt)

    @staticmethod
    def _sha256(password: str, salt: str) -> str:
        password_and_salt = f"{salt}{password}".encode("utf-8")
        return hashlib.sha256(password_and_salt).hexdigest()
