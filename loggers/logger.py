import logging
import time
import json



logger = logging.getLogger("login_attempts")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("login_attempts.log")
formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

attempts_logger = logging.getLogger("attempts")
attempts_logger.setLevel(logging.INFO)
attempts_logger.addHandler(file_handler)



def log_login_attempt(
        username: str,
        result: str | int,
        latency_ms: float,
        seed_group: str,
        timestamp: float = time.time(),
        hash_mode: str = "bcrypt",
        protection_flags: list[str] = None,
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
    logger.info(f"logging {json.dumps(log_entry)}")

    attempts_logger.info(json.dumps(log_entry))

