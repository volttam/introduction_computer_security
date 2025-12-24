from functools import wraps
from fastapi import HTTPException, status


class RateLimiter:
    def __init__(self, rate_limit_enabled: bool, max_attempts: int = 10):
        self.rate_limit_enabled = rate_limit_enabled
        self.max_attempts = max_attempts
        self.attempts_per_user: dict[str, int] = {}

    def check_requests_per_user(self, username: str) -> None:
        if not self.rate_limit_enabled:
            return
        count = self.attempts_per_user.get(username, 0)
        if count >= self.max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts"
            )
        self.attempts_per_user[username] = count + 1

    def limit(self):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                payload = kwargs.get("payload")
                if payload and hasattr(payload, "username"):
                    self.check_requests_per_user(payload.username)
                return func(*args, **kwargs)
            return wrapper
        return decorator
