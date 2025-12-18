import bcrypt
from hashing.password_hasher import PasswordHasher
from logger import logger

class PasswordBcryptHasher(PasswordHasher):
    """
    Password hashing using bcrypt.
    """
    COST = 12

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hahsing password using bcrypt.
        :param password: plain text password
        :return: bcrypt hashed password
        """
        logger.debug(f"Hashing bcrypt password")
        if len(password) < 1:
            raise ValueError("Password must be not empty")
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=PasswordBcryptHasher.COST)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """
        Verifying password using bcrypt.
        :param password: Hashed password
        :param stored_hash: Stored hash
        :return: if password matches stored hash.
        """
        logger.debug(f"Verifying password using bcrypt hash")
        if not stored_hash:
            return False
        password_bytes = password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, stored_hash.encode("utf-8"))