from server.db_manager import DBManager
from server.extra_protections.pepper_manager import PepperManager
from server.settings.settings import Settings
from server.hashing.passwordHasherSelector import PasswordHasherSelector
from server.models.orm.user_handler import UserHandler
from server.extra_protections.rate_limit import RateLimiter
from server.extra_protections.user_lockout import UserLockoutManager
from server.extra_protections.captcha import CaptchaManager
from server.extra_protections.totp import TOTPManager
from server.api_gateway import ApiGateWay

class Context:
    def __init__(self):
        self.settings = Settings()
        self.db_manager = DBManager()
        self.password_hasher_selector = PasswordHasherSelector()
        self.user_handler = UserHandler(db_manager=self.db_manager, pepper_enabled=self.settings.pepper_enabled)
        self.rate_limiter = RateLimiter(self.settings.rate_limit_enabled)
        self.user_lockout_manager = UserLockoutManager(self.settings.user_lockout_enabled)
        self.captcha_manager = CaptchaManager(self.settings.captcha_enabled)
        self.totp_manager = TOTPManager()
        self.pepper_manager = PepperManager(pepper_enabled=self.settings.pepper_enabled, pepper_value=self.settings.pepper_value)
        self.api_gateway = ApiGateWay(rate_limiter=self.rate_limiter, captcha_manager=self.captcha_manager, user_lockout_manager=self.user_lockout_manager)


    @property
    def get_protection_flags(self) -> list[str] | None:
        protection_flags: list[str] = []
        if self.settings.rate_limit_enabled:
            protection_flags.append("rate_limit")
        if self.settings.user_lockout_enabled:
            protection_flags.append("user_lockout")
        if self.settings.captcha_enabled:
            protection_flags.append("captcha")
        if self.settings.totp_enabled:
            protection_flags.append("totp")
        if self.settings.pepper_enabled:
            protection_flags.append("pepper")
        return protection_flags or None


ctx = Context()

