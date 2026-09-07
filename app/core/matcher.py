"""후보 토큰 추출 + SHA-256 대조.

해시는 검색어로 쓸 수 없으므로 "패턴으로 후보 수집 → 해싱 → 대조" 방식을 쓴다.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.core.key_spec import KeySpec
from app.core.redaction import build_snippet

# 토큰 경계: 앞뒤로 키에 쓰일 법한 문자가 붙어 있으면 다른 토큰의 일부로 본다.
_BOUNDARY_CLASS = r"A-Za-z0-9_\-"


@dataclass(frozen=True)
class Candidate:
    value: str
    span: tuple[int, int]


@dataclass(frozen=True)
class MatchResult:
    hash_matched: bool
    candidate: Candidate
    snippet: str


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_pattern(spec: KeySpec) -> re.Pattern[str]:
    """KeySpec 으로 후보 추출용 정규식을 만든다."""
    lo, hi = spec.middle_bounds()
    if lo <= 0 and hi <= 0:
        middle = ""
    elif lo == hi:
        middle = f"[{spec.middle_char_class()}]{{{lo}}}"
    else:
        # 길이 미지정: 첫 postfix 에서 끊기도록 non-greedy
        middle = f"[{spec.middle_char_class()}]{{{max(lo, 0)},{hi}}}?"

    pattern = (
        f"(?<![{_BOUNDARY_CLASS}])"
        + re.escape(spec.prefix)
        + middle
        + re.escape(spec.postfix)
        + f"(?![{_BOUNDARY_CLASS}])"
    )
    return re.compile(pattern)


def iter_candidates(
    text: str,
    spec: KeySpec,
    *,
    pattern: re.Pattern[str] | None = None,
) -> Iterator[Candidate]:
    pat = pattern or build_pattern(spec)
    for m in pat.finditer(text):
        yield Candidate(value=m.group(0), span=m.span())


def scan_text(
    text: str,
    spec: KeySpec,
    *,
    pattern: re.Pattern[str] | None = None,
) -> list[MatchResult]:
    """텍스트에서 후보를 찾아 해시 대조 결과 목록을 돌려준다.

    동일 (값, 위치) 후보는 한 번만 보고한다.
    """
    pat = pattern or build_pattern(spec)
    results: list[MatchResult] = []
    seen: set[tuple[str, tuple[int, int]]] = set()
    for cand in iter_candidates(text, spec, pattern=pat):
        dedup_key = (cand.value, cand.span)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        results.append(
            MatchResult(
                hash_matched=_sha256_hex(cand.value) == spec.sha256,
                candidate=cand,
                snippet=build_snippet(text, cand.span, cand.value),
            )
        )
    return results


def has_confirmed(results: list[MatchResult]) -> bool:
    return any(r.hash_matched for r in results)
