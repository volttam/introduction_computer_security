import bcrypt


class PasswordBcryptHasher:
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