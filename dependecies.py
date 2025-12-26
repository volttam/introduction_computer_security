from models.api_requests.api_requests import LoginRequest
from context import ctx
from loggers.logger import get_logger
from fastapi import Header


logger = get_logger(__name__)

def rate_limit_login_dependency(payload: LoginRequest) -> None:
    """
    rate_limit_login_dependency
    :param payload:
    :return:
    """
    logger.info("Rate limit login dependency")
    ctx.rate_limiter.check_requests_per_user(payload.username)

def user_lockout_dependency(payload: LoginRequest) -> None:
    """
    user_lockout_dependency
    :param payload:
    :return:
    """
    logger.info("User lockout dependency")
    ctx.user_lockout_manager.check_user_lockout(payload.username)


def captcha_dependency(
    payload: LoginRequest,
    captcha_token: str | None = Header(default=None, alias="X-CAPTCHA-TOKEN"),
):
    logger.info(f"Captcha token in depedency is {captcha_token}")
    ctx.captcha_manager.check_captcha_for_user(payload.username, captcha_token)
    try:
        yield
    except Exception:
        ctx.captcha_manager.register_failure(payload.username)
        raise
    else:
        logger.info(f"reset captcha username {payload.username}")
        ctx.captcha_manager.reset(payload.username)

