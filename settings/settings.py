from pydantic_settings import BaseSettings
from typing import Literal
from pathlib import Path
from pydantic import Field

BASE_DIR = Path(__file__).resolve().parent.parent  # project root

class Settings(BaseSettings):
    hash_mode: Literal["argon2id", "bcrypt", "sha256"] = Field(
        default="sha256",
        alias="HASH_MODE",
    )
    seed_group: str = Field(default="0x039C76D")
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    user_lockout_enabled: bool = Field(default=True, alias="USER_LOCKOUT_ENABLED")
    captcha_enabled: bool = Field(default=True, alias="CAPTCHA_ENABLED")
    totp_enabled: bool = Field(default=True, alias="TOTP_ENABLED")
    pepper_enabled: bool = Field(default=True, alias="PEPPER_ENABLED")
    pepper_value: str = Field(default=None, alias="PEPPER_VALUE")

    class Config:
        env_file = BASE_DIR / "config" / ".env"
