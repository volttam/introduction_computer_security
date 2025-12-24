from models.api_requests.api_requests import LoginRequest
from context import ctx
from loggers.logger import get_logger

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
    ctx.user_lockout_manager.check_not_locked(payload.username)
