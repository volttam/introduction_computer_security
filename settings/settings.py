# settings.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Literal
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # project root

class Settings(BaseSettings):
    hashing_mechanism: Literal["argon2id", "bcrypt", "sha256"] = Field(
        default="sha256",
        alias="HASHING_MECHANISM",
    )

    class Config:
        env_file = BASE_DIR / "config" / ".env"
