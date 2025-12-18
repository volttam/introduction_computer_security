
from hashing.argon2id_hashing import PasswordArgon2idHasher
from hashing.bcrypt_hashing import PasswordBcryptHasher
from hashing.sha256_hashing import PasswordSHA256Hasher
from hashing.password_hasher import PasswordHasher
from logger import logger

class PasswordHasherSelector:

    def __init__(self):
        self.sha256_hasher = PasswordSHA256Hasher()
        self.bcrypt_hasher = PasswordBcryptHasher()
        self.argon2id_hasher = PasswordArgon2idHasher()
        self._HASHER_MAP: dict[str, PasswordHasher] = {
        "sha256": self.sha256_hasher,
        "bcrypt": self.bcrypt_hasher,
        "argon2id": self.argon2id_hasher,
    }

    def get_password_hasher(self, hashing_mechanism: str,) -> PasswordHasher:
        """
        Get password hashing mechanism.
        :param hashing_mechanism: Hashing mechanism.
        :return: PasswordHasher
        """
        logger.debug(f"Getting password hasher of {hashing_mechanism}")
        try:
            return self._HASHER_MAP[hashing_mechanism]
        except KeyError:
            raise ValueError(
                f"Unsupported hashing mechanism: {hashing_mechanism}"
            )