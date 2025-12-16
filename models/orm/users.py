from typing import Optional
from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: Optional[int] = Field(default=None,primary_key=True)
    username: str = Field(
        index=True,
        unique=True,
        nullable=False,
        max_length=64,
    )
    email: str = Field(
        index=True,
        unique=True,
        nullable=False,
        max_length=255,
    )
    sha_256_salt_password_hash: str = Field(
        nullable=True
    )
    bcrypt_password_hash: str = Field(
        nullable=True
    )
    argon2id_password_hash: str = Field(
        nullable=True
    )
