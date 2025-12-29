import logging
import json
import time
from context import ctx

attempts_logger = logging.getLogger("auth_attempts")
attempts_logger.setLevel(logging.INFO)
handler = logging.FileHandler("attempts.log")
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
attempts_logger.addHandler(handler)
attempts_logger.propagate = False

def log_login_attempt(
    *,
    timestamp: float = time.time()
    seed_group: str = ctx.settings.seed_group,
    username: str,
    hash_mode: str = ctx.settings.hash_mode,
    protection_flags: list[str],
    result: str,
    latency_ms: float,
):
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
