
from loggers.logger import logger
from file_managers.file_manager import FileManager
from client import ApiClientService
from context import ctx



def brute_force_attack():
    """
    Brute force attack
    :return:
    """
    logger.info("Initializing brute force attack")
    passwords = ctx.file_manager.get_brute_force_passwords
    client_service = ApiClientService()
    client_service.login(username="weak_password_user_1", password="123456")


if __name__ == "__main__":
    brute_force_attack()



