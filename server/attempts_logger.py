import logging
import json
import time
from server.context import ctx
from loggers.logger import logger
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent
ATTEMPTS_LOG_PATH = (LOG_DIR / "attempts.log").resolve()

attempts_logger = logging.getLogger("auth_attempts")
attempts_logger.setLevel(logging.INFO)
handler = logging.FileHandler(ATTEMPTS_LOG_PATH)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
attempts_logger.addHandler(handler)
attempts_logger.propagate = False

def log_login_attempt(
    *,
    seed_group: str = ctx.settings.seed_group,
    username: str,
    hash_mode: str = ctx.settings.hash_mode,
    protection_flags: list[str],
    result: str,
    latency_ms: float,
):
    logger.info("logging attempt")
    timestamp = time.time()
    log_entry = {
        "timestamp": timestamp,
        "seed_group": seed_group,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": latency_ms,
    }
    attempts_logger.info(json.dumps(log_entry))
