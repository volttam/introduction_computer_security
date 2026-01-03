
from loggers.logger import logger
from file_managers.file_manager import FileManager
from client import ApiClientService
from context import ctx

USER_NAME_WEAK_PASSWORD = "weak_password_user_9"
USER_NAME_MEDIUM_PASSWORD = "medium_password_user_2"


def brute_force_attack():
    """
    Brute force attack
    :return:
    """
    logger.info("Initializing brute force attack")
    passwords = ctx.file_manager.get_brute_force_passwords
    client_service = ApiClientService(seed_group=ctx.settings.seed_group)
    protection_flag_fail_attempt = 0
    for password in passwords:
        response = client_service.login(username=USER_NAME_MEDIUM_PASSWORD, password=password)
        if response["status_code"] == 200:
            break
        if response["status_code"] != 200 and response["content"]["detail"] != "Invalid credentials":
            protection_flag_fail_attempt += 1
        if protection_flag_fail_attempt > 100:
            break # if user is blocked by protection flag stop the attack

if __name__ == "__main__":
    brute_force_attack()


