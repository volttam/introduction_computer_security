from fastapi import HTTPException, status
import secrets

from loggers.logger import get_logger

logger = get_logger(__name__)

class CaptchaManager:
    def __init__(self, captcha_enabled: bool, max_attempts: int = 10):
        self.captcha_enabled = captcha_enabled
        self.max_attempts = max_attempts
        self.failed_attempts: dict[str, int] = {}
        self.valid_tokens: set = set()

    def issue_token(self) -> str:
        """
        issues a random token
        :return:
        """
        logger.info(f"issuing random captcha token")
        token = secrets.token_urlsafe(16)
        self.valid_tokens.add(token)
        return token

    def check_captcha_for_user(self, username: str, captcha_token: str | None):
        if not self.captcha_enabled:
            logger.info("captcha disabled")
            return
        logger.info(f"captcha token is {captcha_token} and valid tokens are {self.valid_tokens}")
        if captcha_token and captcha_token in self.valid_tokens:
            self.valid_tokens.discard(captcha_token)
            self.reset_user(username)
            return
        attempts = self.failed_attempts.get(username, 0)
        self.register_failure(username)
        if attempts < self.max_attempts:
            return
        logger.info(f"failed attempts for {username} are {self.failed_attempts[username]}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "captcha_required": True,
            },
        )

    def register_failure(self, username: str):
        """
        Registers a failure
        :param username:
        :return:
        """
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1

    def reset_user(self, username: str) -> None:
        """
        Resets the captcha
        :param username:
        :return:
        """
        self.failed_attempts.pop(username, None)
