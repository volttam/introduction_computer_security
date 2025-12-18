# settings.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Literal
from hashing.config import PasswordHasherConfig


class Settings(BaseSettings):
    password_hasher: Literal["argon2id", "bcrypt", "sha256"] = Field(
        default="argon2id",
        alias="PASSWORD_HASHER",
    )

    class Config:
        env_file = ".env"
