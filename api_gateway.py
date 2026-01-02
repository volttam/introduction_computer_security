from models.api_requests.api_requests import LoginRequest
from loggers.logger import get_logger
from extra_protections.rate_limit import RateLimiter
from extra_protections.user_lockout import UserLockoutManager
from extra_protections.captcha import CaptchaManager
from fastapi import Header

logger = get_logger(__name__)

class ApiGateWay:

    def __init__(self, rate_limiter: RateLimiter, captcha_manager: CaptchaManager, user_lockout_manager: UserLockoutManager):
        self.rate_limiter = rate_limiter
        self.captcha_manager = captcha_manager
        self.user_lockout_manager = user_lockout_manager

    def activate_gateway(self, payload: LoginRequest):
        self.__rate_limit_login_dependency(payload)
        self.__captcha_dependency(payload)
        self.__user_lockout_dependency(payload)


    def __rate_limit_login_dependency(self, payload: LoginRequest) -> None:
        """
        rate_limit_login_dependency
        :param payload:
        :return:
        """
        logger.info("Rate limit login dependency")
        self.rate_limiter.check_requests_per_user(payload.username)

    def __user_lockout_dependency(self, payload: LoginRequest) -> None:
        """
        user_lockout_dependency
        :param payload:
        :return:
        """
        logger.info("User lockout dependency")
        self.user_lockout_manager.check_user_lockout(payload.username)


    def __captcha_dependency(self,
        payload: LoginRequest,
        captcha_token: str | None = Header(default=None, alias="X-CAPTCHA-TOKEN"),
    ):
        logger.info(f"Captcha token in depedency is {captcha_token}")
        self.captcha_manager.check_captcha_for_user(payload.username, captcha_token)
        try:
            yield
        except Exception:
            self.captcha_manager.register_failure(payload.username)
            raise
        else:
            logger.info(f"reset captcha username {payload.username}")
            self.captcha_manager.reset(payload.username)

