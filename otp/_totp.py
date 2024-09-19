"""
For more information, See below:

- HOTP: https://datatracker.ietf.org/doc/html/rfc4226
- TOTP: https://datatracker.ietf.org/doc/html/rfc6238
"""

from base64 import b32decode
from hashlib import sha1
from hmac import HMAC
from time import time
from typing import Callable


class TOTP:
    __PERIOD: int = 30
    __DIGITS: int = 6
    _get_timestamp: Callable[[], float]

    def __init__(self) -> None:
        self._get_timestamp = time

    def generate(self, secret: str) -> str:
        return self._generate_totp(secret=secret, timestamp=self._get_timestamp())

    def verify(self, code: str, *, secret: str, leeway: int = 0) -> bool:
        now = self._get_timestamp()
        valid_codes = {
            self._generate_totp(secret, now + leeway_delta * self.__PERIOD)
            for leeway_delta in range(-leeway, leeway + 1)
        }
        is_valid = code in valid_codes
        return is_valid

    def _generate_totp(self, secret: str, timestamp: float) -> str:
        base32_secret = self._generate_base32_secret(secret)
        time_step = self._calculate_step(timestamp)
        hmac = self._generate_hmac_sha1_value(base32_secret, time_step)
        code = self._generate_code(hmac)
        return code

    def _calculate_step(self, timestamp: float) -> bytes:
        STEP_BYTE_LENGTH = 8
        time_step = int(timestamp // self.__PERIOD)
        time_step_bytes = time_step.to_bytes(STEP_BYTE_LENGTH)
        return time_step_bytes

    def _generate_base32_secret(self, secret: str) -> bytes:
        padding = (8 - len(secret)) % 8
        return b32decode(secret.upper() + "=" * padding)

    def _generate_hmac_sha1_value(self, secret: bytes, message: bytes) -> bytes:
        hmac = HMAC(
            key=secret,
            msg=message,
            digestmod=sha1,
        )
        return hmac.digest()

    def _generate_code(self, hmac: bytes) -> str:
        DYNAMIC_TRUNCATE_MASK = 0xF
        SIGNIFICANT_BIT_MASK = 0x7FFFFFFF
        offset_bits = hmac[-1] & DYNAMIC_TRUNCATE_MASK
        significant_bits = hmac[offset_bits : offset_bits + 4]
        code = int.from_bytes(significant_bits) & SIGNIFICANT_BIT_MASK
        truncated_code = code % 10**self.__DIGITS
        return f"{truncated_code:0{self.__DIGITS}d}"
