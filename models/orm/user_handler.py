from db_manager import DBManager
from models.orm.users import User
from sqlmodel import select


class UserHandler:

    def __init__(self):
        self.db_manager = DBManager()

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

    def get_all_users(self) -> list[User]:
        """
        Return a list of all users stored in the database
        :return:
        """
        session = self.db_manager.get_session()
        query = select(User)
        results = session.exec(query)
        users = []
        for user in results:
            users.append(user)
        return users


