from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import VerifyMismatchError
from argon2 import Type


class PasswordArgon2idHasher:
    """
    Password hashing using Argon2id.

    Parameters:
    - time_cost = 1
    - memory_cost = 64 MB
    - parallelism = 1
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
        if not password:
            raise ValueError("Password must not be empty")

        return PasswordHasher._hasher.hash(password)
