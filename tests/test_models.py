from __future__ import annotations

from whereismykey.core.models import (
    Confidence,
    Severity,
    Verdict,
    classify,
    verdict_for,
)


def test_classify_confirmed() -> None:
    assert classify(True) == (Confidence.CONFIRMED, Severity.CRITICAL)


def test_classify_pattern_only() -> None:
    assert classify(False) == (Confidence.PATTERN_ONLY, Severity.LOW)


def test_verdict_exposed_on_any_confirmed() -> None:
    assert verdict_for([Confidence.PATTERN_ONLY, Confidence.CONFIRMED]) == Verdict.EXPOSED


def test_verdict_not_found_when_empty() -> None:
    assert verdict_for([]) == Verdict.NOT_FOUND


def test_verdict_inconclusive_on_pattern_only() -> None:
    assert verdict_for([Confidence.PATTERN_ONLY]) == Verdict.INCONCLUSIVE


def test_verdict_inconclusive_on_source_errors() -> None:
    assert verdict_for([], had_source_errors=True) == Verdict.INCONCLUSIVE


def test_confirmed_wins_over_source_errors() -> None:
    assert verdict_for([Confidence.CONFIRMED], had_source_errors=True) == Verdict.EXPOSED
