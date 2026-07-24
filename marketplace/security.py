from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque


USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
PASSWORD_MAX_LENGTH = 128
TOTP_STEP_SECONDS = 30


def normalize_username(value: str) -> str:
    return value.strip().lower()


def validate_username(value: str) -> str | None:
    if not USERNAME_RE.fullmatch(value):
        return "아이디는 영문 소문자, 숫자, 밑줄을 사용해 3~20자로 입력해주세요."
    return None


def validate_password(value: str, username: str = "") -> str | None:
    if len(value) < 10:
        return "비밀번호는 10자 이상이어야 합니다."
    if len(value) > PASSWORD_MAX_LENGTH:
        return "비밀번호는 128자 이하여야 합니다."
    if not any(character.isalpha() for character in value) or not any(
        character.isdigit() for character in value
    ):
        return "비밀번호에는 문자와 숫자가 각각 하나 이상 필요합니다."
    if username and username in value.lower():
        return "비밀번호에 아이디를 포함할 수 없습니다."
    return None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return "scrypt$16384$8$1${}${}".format(
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, hash_text = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(hash_text.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (binascii.Error, ValueError, TypeError):
        return False


def new_token(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _totp_key(secret: str) -> bytes:
    normalized = re.sub(r"\s+", "", secret).upper()
    if not normalized:
        raise ValueError("empty TOTP secret")
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)
    if len(key) < 20:
        raise ValueError("TOTP secret must contain at least 160 bits")
    return key


def validate_totp_secret(secret: str) -> bool:
    try:
        _totp_key(secret)
        return True
    except (binascii.Error, ValueError, TypeError):
        return False


def totp_code(secret: str, *, for_time: int | None = None) -> str:
    timestamp = int(time.time()) if for_time is None else int(for_time)
    counter = timestamp // TOTP_STEP_SECONDS
    digest = hmac.new(
        _totp_key(secret),
        counter.to_bytes(8, "big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(
    secret: str,
    code: str,
    *,
    for_time: int | None = None,
    window: int = 1,
) -> bool:
    if not re.fullmatch(r"\d{6}", code.strip()):
        return False
    timestamp = int(time.time()) if for_time is None else int(for_time)
    try:
        return any(
            hmac.compare_digest(
                totp_code(
                    secret,
                    for_time=timestamp + offset * TOTP_STEP_SECONDS,
                ),
                code.strip(),
            )
            for offset in range(-window, window + 1)
        )
    except (ValueError, TypeError):
        return False


class RateLimiter:
    """Small in-memory limiter for login and message endpoints."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            attempts = self._attempts[key]
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            if len(attempts) >= self.limit:
                return False
            attempts.append(now)
            return True

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
