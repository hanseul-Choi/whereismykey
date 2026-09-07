"""점검 대상 키의 명세(KeySpec)와 검증 로직.

우리는 키 평문을 보관하지 않는다. prefix / postfix / 평문의 SHA-256 만 가지고
후보 문자열을 대조한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# 이름 있는 charset → 정규식 문자 클래스 본문
_NAMED_CHARSETS: dict[str, str] = {
    "base62": "A-Za-z0-9",
    "alnum": "A-Za-z0-9",
    "hex": "0-9a-fA-F",
    "base64url": "A-Za-z0-9_-",
}

# length 미지정 시 중간부 길이 범위 및 기본 문자 클래스
DEFAULT_MIDDLE_MIN = 1
DEFAULT_MIDDLE_MAX = 256
DEFAULT_MIDDLE_CLASS = r"A-Za-z0-9_\-"


class Charset(StrEnum):
    BASE62 = "base62"
    ALNUM = "alnum"
    HEX = "hex"
    BASE64URL = "base64url"
    CUSTOM = "custom"


class KeySpecError(ValueError):
    """KeySpec 검증 실패."""


@dataclass(frozen=True)
class KeySpec:
    """점검할 키 한 건의 명세."""

    prefix: str
    postfix: str
    sha256: str
    length: int | None = None
    charset: Charset | None = None
    custom_charset: str | None = None
    name: str | None = None
    key_type: str = "custom"

    def __post_init__(self) -> None:
        errors: list[str] = []
        if not self.prefix:
            errors.append("prefix is required")
        if not self.postfix:
            errors.append("postfix is required")
        if not _SHA256_RE.match(self.sha256 or ""):
            errors.append("sha256 must be 64 hex characters")
        if self.length is not None:
            min_len = len(self.prefix) + len(self.postfix)
            if self.length < min_len:
                errors.append(f"length must be >= len(prefix)+len(postfix) ({min_len})")
        if self.charset is Charset.CUSTOM and not self.custom_charset:
            errors.append("custom_charset is required when charset is 'custom'")
        if errors:
            raise KeySpecError("; ".join(errors))
        # sha256 는 소문자로 정규화해 비교를 단순화한다.
        object.__setattr__(self, "sha256", self.sha256.lower())

    def middle_char_class(self) -> str:
        """중간부(prefix 와 postfix 사이)에 허용되는 문자 클래스 본문."""
        if self.charset is Charset.CUSTOM:
            assert self.custom_charset is not None  # __post_init__ 에서 보장
            return self.custom_charset
        if self.charset is not None:
            return _NAMED_CHARSETS[self.charset.value]
        return DEFAULT_MIDDLE_CLASS

    def middle_bounds(self) -> tuple[int, int]:
        """중간부 길이의 (최소, 최대). length 지정 시 고정값."""
        if self.length is not None:
            mid = self.length - len(self.prefix) - len(self.postfix)
            return (mid, mid)
        return (DEFAULT_MIDDLE_MIN, DEFAULT_MIDDLE_MAX)

    def redacted(self) -> str:
        """리포트 표기용 마스킹 문자열."""
        return f"{self.prefix}…{self.postfix}"
