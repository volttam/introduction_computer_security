import hashlib
import secrets
from dataclasses import dataclass
from hashing.password_hasher import PasswordHasher
from logging.logger import logger

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
    def verify_password(input_password: str, stored_hash: str) -> bool:
        """
        Verify plaintext password against stored SHA256+salt hash.
        :param input_password: Plaintext password entered by user
        :param stored_hash: Stored value in format "salt$hash"
        :return: True if password matches, False otherwise
        """
        logger.debug("Verifying SHA256+salt password")
        if not input_password or not stored_hash:
            return False
        try:
            salt, stored_hash = stored_hash.split("$", 1)
        except ValueError:
            return False
        computed_hash = PasswordSHA256Hasher._sha256(input_password, salt)
        return secrets.compare_digest(computed_hash, stored_hash)
