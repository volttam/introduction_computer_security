import httpx
import time
from loggers.logger import get_logger

logger = get_logger(__name__)
from loggers.attempts_logger import log_login_attempt

class ApiClientService:
    """
    Client-side service that communicates with the FastAPI app.
    """
    def __init__(self, seed_group: str, hash_mode: str, captcha_enabled: bool, base_url: str = "http://127.0.0.1:8001", timeout: float = 6.0, ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.seed_group = seed_group
        self.hash_mode = hash_mode
        self.captcha_enabled = captcha_enabled
        self.captcha_token: str | None = None

    def __fetch_captcha_token(self) -> None:
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
        self.captcha_token = token

    def login(self, username: str, password: str) -> dict:
        """
        Send a login request to the FastAPI server.
        """
        url = f"{self.base_url}/login"
        payload = {
            "username": username,
            "password": password,
        }
        headers = {}
        if self.captcha_enabled and self.captcha_token:
            headers["X-CAPTCHA-TOKEN"] = self.captcha_token
        start_time = time.perf_counter()
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
        latency_ms = (time.perf_counter() - start_time) * 1000
        if response.status_code == 200:
            log_login_attempt(username=username, result=f"{response.status_code} {response.json()["message"]}", latency_ms=latency_ms, seed_group=self.seed_group, hash_mode=self.hash_mode)
        else:
            log_login_attempt(username=username, result=f"{response.status_code} {response.json()["detail"]}", latency_ms=latency_ms, seed_group=self.seed_group, hash_mode=self.hash_mode)
            logger.info(f"captcha required is {response.json().get("captcha_required")}")
            logger.info(f"response is: {response.json()}")
            data = response.json()
            detail= data.get("detail")
            if isinstance(detail, dict) and detail.get("captcha_required") is True is True:
                self.__fetch_captcha_token()
                return self.login(username, password)
        return {
            "status_code": response.status_code,
            "content": response.json() if response.content else None,
            "latency_ms": round(latency_ms, 2),
        }


