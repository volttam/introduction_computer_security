import hashlib
import secrets
from dataclasses import dataclass
from hashing.password_hasher import PasswordHasher
from logger import logger

@dataclass(frozen=True)
class PasswordSHA256Hash:
    hash: str
    salt: str


class PasswordSHA256Hasher(PasswordHasher):
    """
    Password hasher using SHA-256 with per-password salt
    """
    SALT_BYTES = 16  # 128-bit salt

    @staticmethod
    def hash_password(password: str) -> PasswordSHA256Hash:
        """
        Hash password by sha256
        param password: Password string
        :return: sha256+salt hash
        """
        logger.debug("Hashing password using sha256")
        if len(password) < 1:
            raise ValueError("Password must be not empty")
        salt = secrets.token_hex(PasswordSHA256Hasher.SALT_BYTES)
        hash_value = PasswordSHA256Hasher._sha256(password, salt)
        return PasswordSHA256Hash(hash=hash_value, salt=salt)

    @staticmethod
    def _sha256(password: str, salt: str) -> str:
        """
        Combine salt and sha256 hash
        :param password: Password string
        :param salt: Salt string
        :return: hashed salt and sha256 hash
        """
        logger.debug("Combine salt and sha256 hash")
        password_and_salt = f"{salt}{password}".encode("utf-8")
        return hashlib.sha256(password_and_salt).hexdigest()

    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """
        Verify password hash by sha256
        :param password: Password string
        :param stored_hash: stored hash
        :param salt: salt string
        :return: if password hash matches stored hash
        """
        logger.debug("Verify password hash")
        if not stored_hash or not salt:
            return False
        calculated = PasswordSHA256Hasher._sha256(password, salt)
        return secrets.compare_digest(calculated, stored_hash)
