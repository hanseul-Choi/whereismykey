"""스캔 결과 조립 및 권고안 생성."""

from __future__ import annotations

from whereismykey.core.key_spec import KeySpec
from whereismykey.core.models import Confidence, Finding, ScanResult, Verdict, verdict_for
from whereismykey.sources.base import ScanOptions

DEFAULT_EXPOSED_RECOMMENDATIONS = [
    "노출된 키를 즉시 폐기(revoke)하고 새 키를 발급하세요.",
    (
        "파일 수정만으로는 부족합니다 — 커밋 히스토리·포크·검색 캐시에 남으므로 "
        "키 폐기가 유일한 해결책입니다."
    ),
    "노출 페이지 소유자에게 아래 템플릿으로 삭제를 요청하세요.",
]

DEFAULT_INCONCLUSIVE_RECOMMENDATIONS = [
    "일부 소스 검색에서 오류가 발생했거나 패턴 일치만 확인되었습니다.",
    "네트워크/API 토큰 설정을 확인하고 필요 시 대상 저장소 및 페이지를 직접 확인하세요.",
]

DEFAULT_NOT_FOUND_RECOMMENDATIONS = [
    "공개 저장소 및 웹 검색 결과에서 일치하는 키가 발견되지 않았습니다.",
    "비공개 저장소 또는 내부 시스템의 노출 여부는 별도로 점검하시기 바랍니다.",
]


def build_takedown_message(urls: list[str], key_redacted: str) -> str:
    """노출 페이지 소유자에게 전달할 삭제 요청 메시지 템플릿 생성."""
    url_text = "<노출 URL>" if not urls else "\n".join(f"- {u}" for u in urls)

    return (
        "안녕하세요,\n"
        "귀하께서 관리하시는 아래 페이지에 유효한 API 자격증명으로 보이는 문자열("
        f"{key_redacted}"
        ")이 포함되어 있어 연락드립니다.\n\n"
        f"{url_text}\n\n"
        "해당 문자열의 삭제 또는 마스킹 처리를 정중히 요청드립니다.\n"
        "감사합니다."
    )


def build_scan_result(
    spec: KeySpec,
    findings: list[Finding],
    errors: list[str],
    options: ScanOptions,
) -> ScanResult:
    """스캔 결과 조립."""
    all_confidences = [f.confidence for f in findings]
    verdict = verdict_for(all_confidences, had_source_errors=bool(errors))

    # include_pattern_only 옵션 적용: findings 목록 필터링
    filtered_findings = findings
    if not options.include_pattern_only:
        filtered_findings = [f for f in findings if f.confidence == Confidence.CONFIRMED]

    key_redacted = spec.redacted()

    # 권고안 결정
    if verdict == Verdict.EXPOSED:
        recommendations = list(DEFAULT_EXPOSED_RECOMMENDATIONS)
        exposed_urls = [f.url for f in filtered_findings if f.confidence == Confidence.CONFIRMED]
        takedown_template = build_takedown_message(exposed_urls, key_redacted)
    elif verdict == Verdict.INCONCLUSIVE:
        recommendations = list(DEFAULT_INCONCLUSIVE_RECOMMENDATIONS)
        pattern_urls = [f.url for f in filtered_findings]
        takedown_template = build_takedown_message(pattern_urls, key_redacted)
    else:
        recommendations = list(DEFAULT_NOT_FOUND_RECOMMENDATIONS)
        takedown_template = ""

    return ScanResult(
        verdict=verdict,
        key_name=spec.name,
        key_redacted=key_redacted,
        findings=filtered_findings,
        recommendations=recommendations,
        takedown_message_template=takedown_template,
    )
