from server.models.api_requests.api_requests import LoginRequest
from loggers.logger import get_logger
from server.extra_protections.rate_limit import RateLimiter
from server.extra_protections.user_lockout import UserLockoutManager
from server.extra_protections.captcha import CaptchaManager

logger = get_logger(__name__)

class ApiGateWay:

    def __init__(self, rate_limiter: RateLimiter, captcha_manager: CaptchaManager, user_lockout_manager: UserLockoutManager):
        self.rate_limiter = rate_limiter
        self.captcha_manager = captcha_manager
        self.user_lockout_manager = user_lockout_manager


    def activate_gateway(self, payload: LoginRequest, captcha_token: str | None) -> None:
        self.user_lockout_manager.check_user_lockout(payload.username)
        self.rate_limiter.check_requests_per_user(payload.username)
        self.captcha_manager.check_captcha_for_user(payload.username, captcha_token)


    def reset_user(self, payload: LoginRequest) -> None:
        self.user_lockout_manager.reset_user(payload.username)
        self.rate_limiter.reset_user(payload.username)
        self.captcha_manager.reset_user(payload.username)



