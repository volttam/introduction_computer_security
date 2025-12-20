# settings.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Literal
from pathlib import Path
from pydantic import Field

BASE_DIR = Path(__file__).resolve().parent.parent  # project root

class Settings(BaseSettings):
    hash_mode: Literal["argon2id", "bcrypt", "sha256"] = Field(
        default="sha256",
        alias="HASHING_MECHANISM",
    )
    seed_group: str = Field(default="0x039C76D")

    class Config:
        env_file = BASE_DIR / "config" / ".env"
