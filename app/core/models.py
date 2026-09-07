"""도메인 열거형과 판정 로직 (네트워크 무관)."""

from __future__ import annotations

from enum import StrEnum


class Confidence(StrEnum):
    """후보가 대상 키일 확신도."""

    CONFIRMED = "confirmed"  # SHA-256 일치
    PATTERN_ONLY = "pattern_only"  # 패턴만 일치, 해시 불일치


class Severity(StrEnum):
    CRITICAL = "critical"
    LOW = "low"


class Verdict(StrEnum):
    EXPOSED = "exposed"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"


class Stage(StrEnum):
    GITHUB = "github"
    WEB = "web"


_SEVERITY_BY_CONFIDENCE: dict[Confidence, Severity] = {
    Confidence.CONFIRMED: Severity.CRITICAL,
    Confidence.PATTERN_ONLY: Severity.LOW,
}


def classify(hash_matched: bool) -> tuple[Confidence, Severity]:
    """해시 일치 여부 → (확신도, 심각도)."""
    confidence = Confidence.CONFIRMED if hash_matched else Confidence.PATTERN_ONLY
    return confidence, _SEVERITY_BY_CONFIDENCE[confidence]


def verdict_for(
    confidences: list[Confidence],
    *,
    had_source_errors: bool = False,
) -> Verdict:
    """발견된 확신도 목록으로 최종 판정을 낸다.

    - confirmed 1건 이상            → EXPOSED
    - 소스 오류가 있었다            → INCONCLUSIVE
    - pattern_only 만 있음          → INCONCLUSIVE
    - 아무것도 없음                 → NOT_FOUND
    """
    if Confidence.CONFIRMED in confidences:
        return Verdict.EXPOSED
    if had_source_errors:
        return Verdict.INCONCLUSIVE
    if Confidence.PATTERN_ONLY in confidences:
        return Verdict.INCONCLUSIVE
    return Verdict.NOT_FOUND
