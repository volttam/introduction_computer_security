from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import time

import pyotp

from loggers.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TOTPCheckResult:
    success: bool
    reason: str | None
    timecode: int | None


class TOTPManager:
    """
    Handles TOTP generation and verification for the login_totp endpoint
    """

    def __init__(self, interval_seconds: int = 30, code_digits: int = 6, window: int = 1) -> None:
        self.interval = interval_seconds
        self.digits = code_digits
        self.window = window

    def create_secret(self) -> str:
        secret = pyotp.random_base32()
        logger.info("Created TOTP secret for user")
        return secret

    def _build_totp(self, secret: str) -> pyotp.TOTP:
        return pyotp.TOTP(secret, interval=self.interval, digits=self.digits)

    def _step_from_ts(self, ts: float) -> int:
        return int(ts // self.interval)

    def _step_from_datetime(self, dt: datetime) -> int:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return self._step_from_ts(dt.timestamp())

    def generate_code(self, secret: str, ts: float | None = None) -> str:
        totp = self._build_totp(secret)
        now = ts if ts is not None else time.time()
        return totp.at(now)

    def validate_code(self, secret: str,code: str, last_used_at: datetime | None) -> TOTPCheckResult:
        totp = self._build_totp(secret)
        now_ts = time.time()
        current_step = self._step_from_ts(now_ts)
        last_step = None
        if last_used_at is not None:
            last_step = self._step_from_datetime(last_used_at)
        for shift in range(-self.window, self.window + 1):
            step = current_step + shift
            if step < 0:
                continue
            step_ts = step * self.interval
            is_valid = totp.verify(code, for_time=step_ts, valid_window=0)
            if not is_valid:
                continue
            if last_step is not None and step == last_step:
                logger.warning("TOTP reuse detected for same time window")
                return TOTPCheckResult(success=False, reason="Code was already used", timecode=step)
            return TOTPCheckResult(success=True, reason=None, timecode=step)
        logger.warning("Invalid or expired TOTP")
        return TOTPCheckResult(success=False, reason="Invalid or expired TOTP code", timecode=current_step,)

    def datetime_from_step(self, step: int) -> datetime:
        return datetime.fromtimestamp(step * self.interval, tz=timezone.utc,)
