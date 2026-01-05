from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime

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
        nullable=False
    )
    sha_256_salt_password_hash_peppered: str = Field(
        default=None,
        nullable=True,
    )
    bcrypt_password_hash: str = Field(
        nullable=False
    )
    bcrypt_password_hash_peppered: str = Field(
        default=None,
        nullable=True,
    )
    argon2id_password_hash: str = Field(
        nullable=False
    )
    argon2id_password_hash_peppered: str = Field(
        default=None,
        nullable=True,
    )
    totp_secret: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Base32 encoded TOTP secret",
    )
    totp_last_verified_at: Optional[datetime] = Field(
        default=None,
        description="Last successful TOTP verification timestamp",
    )
