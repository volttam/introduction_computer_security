from db_manager import DBManager
from settings.settings import Settings
from hashing.passwordHasherSelector import PasswordHasherSelector
from models.orm.user_handler import UserHandler
from file_managers.file_manager import FileManager

class Context:
    def __init__(self):
        self.db_manager = DBManager()
        self.settings = Settings()
        self.password_hasher_selector = PasswordHasherSelector()
        self.user_handler = UserHandler()
        self.file_manager = FileManager()


ctx = Context()

