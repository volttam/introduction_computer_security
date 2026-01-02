import time
from fastapi import HTTPException, status
from loggers.logger import get_logger

logger = get_logger(__name__)

class RateLimiter:
    def __init__(
        self,
        rate_limit_enabled: bool,
        max_attempts: int = 10,
        window_seconds: int = 60,
    ):
        self.rate_limit_enabled = rate_limit_enabled
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts_per_user: dict[str, list[float]] = {}

    def check_requests_per_user(self, username: str) -> None:
        """
        check requests per user
        :param username:
        :return:
        """
        if not self.rate_limit_enabled:
            return
        now = time.time()
        logger.info(f"Checking requests per user: {username}")
        attempts = self.attempts_per_user.get(username, [])
        valid_attempts = [
            ts for ts in attempts if now - ts < self.window_seconds
        ]
        if len(valid_attempts) >= self.max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts, please try again later",
            )
        valid_attempts.append(now)
        self.attempts_per_user[username] = valid_attempts
