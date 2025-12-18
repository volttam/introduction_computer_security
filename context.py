
from db_manager import DBManager
from settings.settings import Settings
from hashing.passwordHasherSelector import PasswordHasherSelector

class Context:
    def __init__(self):
        self.db_manager = DBManager()
        self.settings = Settings()
        self.password_hasher_selector = PasswordHasherSelector()

