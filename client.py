import httpx
import time
from loggers.logger import logger
from loggers.attempts_logger import log_login_attempt
from context import ctx

class ApiClientService:
    """
    Client-side service that communicates with the FastAPI app.
    """
    def __init__(self, base_url: str = "http://127.0.0.1:8001", timeout: float = 6.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def login(self, username: str, password: str) -> dict:
        """
        Send a login request to the FastAPI server.
        """
        url = f"{self.base_url}/login"
        payload = {
            "username": username,
            "password": password,
        }
        start_time = time.perf_counter()
        logger.info(f"Login request to {url}")
        try:
            response = httpx.post(
                url,
                json=payload,
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            logger.error(f"Request failed: {exc}")
            raise
        latency_ms = (time.perf_counter() - start_time) * 1000
        log_login_attempt(username=username, result=f"{response.status_code} {response.json()}", latency_ms=(time.perf_counter() - start_time) * 1000, seed_group=ctx.settings.seed_group, hash_mode=ctx.settings.hash_mode)
        return {
            "status_code": response.status_code,
            "content": response.json() if response.content else None,
            "latency_ms": round(latency_ms, 2),
        }
