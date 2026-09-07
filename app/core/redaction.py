"""키/비밀 문자열을 안전하게 마스킹하는 단일 지점.

응답·로그·예외 메시지 어디에서도 전체 키가 노출되지 않도록,
모든 마스킹은 이 모듈의 함수를 거친다.
"""

from __future__ import annotations

import logging

MASK = "…"  # …


def redact_key(value: str | None, *, prefix_len: int = 7, postfix_len: int = 7) -> str:
    """임의 문자열을 ``prefix…postfix`` 형태로 마스킹한다.

    앞뒤로 남길 길이의 합보다 짧으면 전체를 가린다.
    """
    if not value:
        return ""
    if len(value) <= prefix_len + postfix_len:
        return MASK
    return f"{value[:prefix_len]}{MASK}{value[-postfix_len:]}"


def redact_in_text(text: str, secrets: list[str], *, replacement: str | None = None) -> str:
    """텍스트에서 주어진 비밀 문자열들을 마스킹 값으로 치환한다."""
    out = text
    for secret in secrets:
        if not secret:
            continue
        rep = replacement if replacement is not None else redact_key(secret)
        out = out.replace(secret, rep)
    return out


def build_snippet(
    text: str,
    span: tuple[int, int],
    secret: str,
    *,
    context: int = 48,
) -> str:
    """매치 구간 주변 문맥을 잘라내되, 매치된 비밀은 마스킹한 스니펫을 만든다."""
    start, end = span
    lo = max(0, start - context)
    hi = min(len(text), end + context)
    body = f"{text[lo:start]}{redact_key(secret)}{text[end:hi]}"
    body = " ".join(body.split())
    if lo > 0:
        body = MASK + body
    if hi < len(text):
        body = body + MASK
    return body


class RedactingLogFilter(logging.Filter):
    """등록된 비밀 문자열을 로그 메시지에서 마스킹하는 로깅 필터."""

    def __init__(self, secrets: list[str] | None = None) -> None:
        super().__init__()
        self._secrets: list[str] = [s for s in (secrets or []) if s]

    def add_secret(self, secret: str) -> None:
        if secret and secret not in self._secrets:
            self._secrets.append(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            original = record.getMessage()
            redacted = redact_in_text(original, self._secrets)
            if redacted != original:
                record.msg = redacted
                record.args = ()
        return True
