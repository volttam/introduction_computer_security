from fastapi import HTTPException, status
from loggers.logger import get_logger

logger = get_logger(__name__)

class UserLockoutManager:
    def __init__(
        self,
        user_lockout_enabled: bool,
        max_failed_attempts: int = 10,
    ):
        self.user_lockout_enabled = user_lockout_enabled
        self.max_failed_attempts = max_failed_attempts
        self.failed_attempts: dict[str, int] = {}
        self.locked_users: set[str] = set()

    def check_not_locked(self, username: str) -> None:
        if not self.user_lockout_enabled:
            return
        if username in self.locked_users:
            logger.info(f"Login attempt on locked account: {username}")
            raise HTTPException( status_code=status.HTTP_423_LOCKED,detail="Account locked due to too many failed login attempts",)

    def register_failed_attempt(self, username: str) -> None:
        if not self.user_lockout_enabled:
            return
        count = self.failed_attempts.get(username, 0) + 1
        self.failed_attempts[username] = count
        logger.info(f"Failed login attempt {count}/{self.max_failed_attempts} for user {username}")
        if count >= self.max_failed_attempts:
            self.locked_users.add(username)
            logger.warning(f"User {username} has been locked out")
