from db_manager import DBManager
from settings.settings import Settings
from hashing.passwordHasherSelector import PasswordHasherSelector
from models.orm.user_handler import UserHandler
from file_managers.file_manager import FileManager
from extra_protections.rate_limit import RateLimiter
from extra_protections.user_lockout import UserLockoutManager
from extra_protections.captcha import CaptchaManager

class Context:
    def __init__(self):
        self.settings = Settings()
        self.db_manager = DBManager()
        self.password_hasher_selector = PasswordHasherSelector()
        self.user_handler = UserHandler(db_manager=self.db_manager)
        self.file_manager = FileManager()
        self.rate_limiter = RateLimiter(self.settings.rate_limit_enabled)
        self.user_lockout_manager = UserLockoutManager(self.settings.user_lockout_enabled)
        self.captcha_manager = CaptchaManager(self.settings.captcha_enabled)


ctx = Context()

