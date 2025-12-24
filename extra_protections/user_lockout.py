from fastapi import HTTPException, status
from loggers.logger import get_logger

logger = get_logger(__name__)

class UserLockoutManager:
    def __init__(
        self,
        lockout_enabled: bool,
        max_attempts: int = 10,
    ):
        self.lockout_enabled = lockout_enabled
        self.max_attempts = max_attempts
        self.failed_attempts: dict[str, int] = {}
        self.locked_users: set[str] = set()

    def check_user_lockout(self, username: str) -> None:
        """
        Lockout check + mutation.
        """
        if not self.lockout_enabled:
            return
        logger.info(f"Checking lockout for user: {username}")
        if username in self.locked_users:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account locked due to too many failed login attempts",
            )
        count = self.failed_attempts.get(username, 0) + 1
        self.failed_attempts[username] = count
        logger.info(f"Failed attempts for {username}: {count}")
        if count >= self.max_attempts:
            self.locked_users.add(username)
            logger.warning(f"User {username} locked out")
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account locked due to too many failed login attempts",
            )
