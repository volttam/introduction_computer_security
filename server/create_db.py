from typing import Optional
from sqlmodel import Session, select
from datetime import datetime
from models.orm.users import User
from db_manager import DBManager
from hashing.bcrypt_hashing import PasswordBcryptHasher
from hashing.argon2id_hashing import PasswordArgon2idHasher
from hashing.sha256_hashing import PasswordSHA256Hasher
from extra_protections.totp import TOTPManager

pepper = "zN3VYc4p9nBqkR4sM1Z2xFQe7K6P8tL0oWmA5dE="

def _build_user(username: str, email: str, password: str, password_pepper: str) -> User:
    """Create a User with password hashes and TOTP secret."""

    sha_hashed = PasswordSHA256Hasher.hash_password(password)
    sha_peppered_password = PasswordSHA256Hasher.hash_password(password_pepper)
    salted_hash = f"{sha_hashed.salt}${sha_hashed.hash}"
    salted_hash_peppered = f"{sha_peppered_password.salt}${sha_peppered_password.hash}"

    totp_manager = TOTPManager()

    return User(
        username=username,
        email=email,
        sha_256_salt_password_hash=salted_hash,
        sha_256_salt_password_hash_peppered=salted_hash_peppered,
        argon2id_password_hash=PasswordArgon2idHasher.hash_password(password),
        argon2id_password_hash_peppered=PasswordArgon2idHasher.hash_password(password_pepper),
        bcrypt_password_hash=PasswordBcryptHasher.hash_password(password),
        bcrypt_password_hash_peppered=PasswordBcryptHasher.hash_password(password_pepper),
        totp_secret=totp_manager.create_secret(),
        totp_last_verified_at=None,
    )


def _seed_user_batch(session: Session) -> None:
    """Insert test users with varying password strength."""

    weak_passwords = [
        "123456", "password", "tamir", "maya", "dadmom",
        "brothersister", "iloveyou", "horse", "dragon", "sunshine",
    ]

    medium_passwords = [
        "Winter2024", "CoffeeTime7", "BlueSky88", "RiverRun12",
        "SimplePass9", "HappyDays5", "Garden1234",
        "OrangeMoon3", "Laptop2023", "PythonFun6",
    ]

    strong_passwords = [
        "R3d!Fox&Trail77", "S!lver$ea12345", "NightH@wk_2048",
        "Sunset^Crest902", "Blu3Berry!Punch", "Tw!light*Ridge6",
        "MapleLeaf$ky09", "V!oletStorm#12", "Starlight@Road5",
        "CedarPeak!4032",
    ]

    user_entries = []

    for idx, password in enumerate(weak_passwords, 1):
        user_entries.append(
            _build_user(
                username=f"weak_password_user_{idx}",
                email=f"weak_password_{idx}@example.com",
                password=password,
                password_pepper=f"{password}{pepper}"
            )
        )

    for idx, password in enumerate(medium_passwords, 1):
        user_entries.append(
            _build_user(
                username=f"medium_password_user_{idx}",
                email=f"medium_password_{idx}@example.com",
                password=password,
                password_pepper=f"{password}{pepper}"
            )
        )

    for idx, password in enumerate(strong_passwords, 1):
        user_entries.append(
            _build_user(
                username=f"strong_password_user_{idx}",
                email=f"strong_password_{idx}@example.com",
                password=password,
                password_pepper=f"{password}{pepper}"
            )
        )

    existing_usernames = {
        username for (username,) in session.exec(select(User.username)).all()
    }

    for user in user_entries:
        if user.username not in existing_usernames:
            session.add(user)

    session.commit()


def seed_users() -> None:
    db_manager = DBManager()
    session_gen = db_manager.get_session()
    session = next(session_gen)
    try:
        _seed_user_batch(session)
        session.commit()
    finally:
        session.close()

if __name__ == "__main__":
    seed_users()