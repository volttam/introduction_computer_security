from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hmac
import hashlib
import os
import time
import urllib.parse

from loggers.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TOTPVerificationResult:
    success: bool
    reason: str | None
    timecode: int | None


class TOTPManager:
    """
    Handles TOTP generation and verification for the login_totp endpoint.
    """

    def __init__(
        self,
        period: int = 30,
        digits: int = 6,
        valid_window_steps: int = 1,
    ) -> None:
        self.period = period
        self.digits = digits
        self.valid_window_steps = valid_window_steps

    def generate_secret(self) -> str:
        secret = base64.b32encode(os.urandom(20)).decode("utf-8").rstrip("=")
        logger.info("Generated new TOTP secret")
        return secret

    def _decode_secret(self, secret: str) -> bytes:
        padding = "=" * (-len(secret) % 8)
        return base64.b32decode(secret + padding, casefold=True)

    def _timecode(self, timestamp: float) -> int:
        return int(timestamp // self.period)

    def _hotp(self, secret: bytes, counter: int) -> str:
        counter_bytes = counter.to_bytes(8, "big")
        hmac_digest = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0F
        code_int = (
            int.from_bytes(hmac_digest[offset : offset + 4], "big") & 0x7FFFFFFF
        ) % (10**self.digits)
        return str(code_int).zfill(self.digits)

    def generate_current_code(self, secret: str, for_time: float | None = None) -> str:
        now = for_time if for_time is not None else time.time()
        secret_bytes = self._decode_secret(secret)
        return self._hotp(secret_bytes, self._timecode(now))

    def _timecode_from_datetime(self, value: datetime) -> int:
        aware_dt = value
        if value.tzinfo is None:
            aware_dt = value.replace(tzinfo=timezone.utc)
        return self._timecode(aware_dt.timestamp())

    def verify_code(
        self,
        secret: str,
        code: str,
        last_verified_at: datetime | None,
    ) -> TOTPVerificationResult:
        """
        Verify a TOTP code
        """
        secret_bytes = self._decode_secret(secret)
        current_timecode = self._timecode(time.time())
        last_timecode = None
        if last_verified_at is not None:
            last_timecode = self._timecode_from_datetime(last_verified_at)

        for offset in range(-self.valid_window_steps, self.valid_window_steps + 1):
            candidate_timecode = current_timecode + offset
            if candidate_timecode < 0:
                continue
            expected_code = self._hotp(secret_bytes, candidate_timecode)
            if expected_code == code:
                if last_timecode is not None and candidate_timecode == last_timecode:
                    logger.warning("Rejected reused TOTP code at the same time step")
                    return TOTPVerificationResult(
                        success=False,
                        reason="TOTP code already used recently",
                        timecode=candidate_timecode,
                    )
                return TOTPVerificationResult(
                    success=True,
                    reason=None,
                    timecode=candidate_timecode,
                )

        logger.warning("Invalid or expired TOTP code")
        return TOTPVerificationResult(
            success=False,
            reason="Invalid or expired TOTP code",
            timecode=current_timecode,
        )

    def timestamp_from_timecode(self, timecode: int) -> datetime:
        """
        Convert a timecode (TOTP step) back to a UTC datetime
        """
        return datetime.fromtimestamp(timecode * self.period, tz=timezone.utc)