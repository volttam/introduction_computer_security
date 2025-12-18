# settings.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Literal



class Settings(BaseSettings):
    hashing_mechanism: Literal["argon2id", "bcrypt", "sha256"] = Field(
        default="sha256",
        alias="HASHING_MECHANISM",
    )

    class Config:
        env_file = ".env"
