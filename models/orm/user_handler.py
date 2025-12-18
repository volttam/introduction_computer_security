from models.orm.users import User


class UserHandler:

    @staticmethod
    def get_stored_password_hash(user: User, hashing_mechanism: str) -> str:
        """
        Return the correct stored password hash for the given hashing mechanism.
        """
        hash_map = {
            "sha256": user.sha_256_salt_password_hash,
            "bcrypt": user.bcrypt_password_hash,
            "argon2id": user.argon2id_password_hash,
        }
        try:
            return hash_map[hashing_mechanism]
        except KeyError:
            raise ValueError(
                f"Unsupported hashing mechanism: {hashing_mechanism}"
            )
