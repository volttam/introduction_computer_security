import httpx
import time
from loggers.logger import get_logger
from pathlib import Path
import json
from extra_protections.totp import TOTPManager
logger = get_logger(__name__)
from loggers.attempts_logger import log_login_attempt

class ApiClientService:
    """
    Client-side service that communicates with the FastAPI app.
    """
    BASE_DIR = Path(__file__).resolve().parent
    TOTP_CODE = "000000"

    def __init__(self,
        seed_group: str,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float = 6.0,
        totp_period: int = 30,
        totp_digits: int = 6
        ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.seed_group = seed_group
        self.totp_period = totp_period
        self.totp_digits = totp_digits

    def __fetch_captcha_token(self) -> str:
        """
        Fetches the captcha token
        :return:
        """
        url = f"{self.base_url}/admin/get_captcha_token"
        params = {"group_seed": self.seed_group}
        logger.info(f"Fetching captcha token from: {url}")
        response = httpx.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        token = response.json()["captcha_token"]
        logger.info(f"Captcha token: {token}")
        return token

    def login(self, username: str, password: str, headers: dict= None) -> dict:
        """
        Send a login request to the FastAPI server.
        """
        url = f"{self.base_url}/login"
        payload = {
            "username": username,
            "password": password,
        }
        logger.info(f"Login request to {url}")
        try:
            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            logger.error(f"Request failed: {exc}")
            raise
        if response.status_code == 200:
            logger.info(f"response is {response.json()}")
            if response.json()["message"] == "Credentials are valid but totp code is required":
                self.login_totp(username)
        else:
            logger.info(f"response is: {response.json()}")
            data = response.json()
            detail= data.get("detail")
            if isinstance(detail, dict) and detail.get("captcha_required") is True is True:
                if headers is None:
                    headers = {}
                headers["X-CAPTCHA-TOKEN"] = self.__fetch_captcha_token()
                return self.login(username, password, headers)
        return {
            "status_code": response.status_code,
            "content": response.json() if response.content else None,
        }

    def login_totp(self, username: str) -> dict:
        """
        Send a login_totp request
        """
        url = f"{self.base_url}/login_totp"
        payload = {
            "username": username,
            "totp_code": self.TOTP_CODE,
        }
        logger.info(f"Login TOTP request to {url}")
        try:
            response = httpx.post(
                url,
                json=payload,
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            logger.error(f"Request failed: {exc}")
            raise
        return {
            "status_code": response.status_code,
            "content": response.json() if response.content else None
        }

