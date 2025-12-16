from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import VerifyMismatchError
from argon2 import Type
from hashing.password_hasher import PasswordHasher


class PasswordArgon2idHasher(PasswordHasher):
    """
    Password hashing using Argon2id.
    """

    _hasher = _Argon2Hasher(
        time_cost=1,
        memory_cost=64 * 1024,  # argon2 expects KB
        parallelism=1,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )

    @staticmethod
    def hash_password(password: str) -> str:
        if len(password) < 1:
            raise ValueError("Password must not be empty")
        return PasswordArgon2idHasher._hasher.hash(password)

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        if not stored_hash:
            return False
        try:
            PasswordArgon2idHasher._hasher.verify(stored_hash, password)
        except VerifyMismatchError:
            return False
        return True
