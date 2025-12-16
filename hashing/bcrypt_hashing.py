import bcrypt
from hashing.password_hasher import PasswordHasher

class PasswordBcryptHasher(PasswordHasher):
    """
    Password hashing using bcrypt.
    """
    COST = 12

    @staticmethod
    def hash_password(password: str) -> str:
        if len(password) < 1:
            raise ValueError("Password must be not empty")
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=PasswordBcryptHasher.COST)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        if not stored_hash:
            return False
        password_bytes = password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, stored_hash.encode("utf-8"))