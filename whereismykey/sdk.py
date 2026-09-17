"""whereismykey Python SDK.

파이썬 코드에서 라이브러리로 직접 import하여 키 노출을 점검할 수 있는 최상위 인터페이스.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from whereismykey.config import Settings, get_settings
from whereismykey.core.key_spec import KeySpec
from whereismykey.core.models import Finding, ScanResult, Stage
from whereismykey.report.builder import build_scan_result
from whereismykey.scanner.stages import (
    create_sources_for_stages,
    determine_active_stages,
)
from whereismykey.sources.base import ScanOptions

logger = logging.getLogger(__name__)


def _resolve_spec(
    target: KeySpec | str | None = None,
    *,
    key: str | None = None,
    spec: KeySpec | None = None,
    prefix_len: int = 8,
    postfix_len: int = 6,
    name: str | None = None,
) -> KeySpec:
    if isinstance(target, KeySpec):
        return target
    if isinstance(target, str):
        return KeySpec.from_key(target, prefix_len=prefix_len, postfix_len=postfix_len, name=name)
    if spec is not None:
        return spec
    if key is not None:
        return KeySpec.from_key(key, prefix_len=prefix_len, postfix_len=postfix_len, name=name)
    msg = "점검할 대상이 지정되지 않았습니다. target, spec 또는 key 중 하나를 지정해주세요."
    raise ValueError(msg)


async def scan_async(
    target: KeySpec | str | None = None,
    *,
    key: str | None = None,
    spec: KeySpec | None = None,
    stages: Sequence[Stage | str] | None = None,
    options: ScanOptions | None = None,
    deep_scan: bool = True,
    github_token: str | None = None,
    brave_api_key: str | None = None,
    crawl_urls: list[str] | None = None,
    crawl_max_depth: int = 1,
    settings: Settings | None = None,
    prefix_len: int = 8,
    postfix_len: int = 6,
    name: str | None = None,
) -> ScanResult:
    """비동기 방식으로 API 키 노출 여부를 점검합니다.

    Args:
        target: 점검 대상 KeySpec 또는 평문 키 문자열.
        key: 평문 키 문자열 (지정 시 로컬에서 즉시 SHA-256 해시 및 prefix/postfix 분할).
        spec: 점검 대상 KeySpec 객체.
        stages: 점검할 스테이지 목록 (선택: "github", "web", "crawl"). 기본: ["github", "web"].
        options: 스캔 세부 옵션 (기본: ScanOptions()).
        deep_scan: 페이지네이션 전수 스캔 여부 (기본: True).
        github_token: GitHub Code Search API 인증 토큰 (설정 파일보다 우선).
        brave_api_key: Brave Search API 인증 키 (설정 파일보다 우선).
        crawl_urls: 웹 크롤러 탐색 시 추가 점검할 시드 웹 URL 목록 (선택).
        crawl_max_depth: 시드 URL 내부 링크 탐색 깊이 (기본: 1).
        settings: 사용자 정의 Settings 객체 (선택).
        prefix_len: key 지정 시 접두사 길이 (기본: 8).
        postfix_len: key 지정 시 접미사 길이 (기본: 6).
        name: 키 식별용 이름 (선택).

    Returns:
        ScanResult: 판정(verdict), 발견 항목(findings), 권고사항, 삭제 템플릿 등.
    """
    resolved_spec = _resolve_spec(
        target,
        key=key,
        spec=spec,
        prefix_len=prefix_len,
        postfix_len=postfix_len,
        name=name,
    )
    base_settings = settings or get_settings()

    # 파라미터로 명시 전달된 토큰으로 오버라이드
    overrides: dict[str, str | None] = {}
    if github_token is not None:
        overrides["github_token"] = github_token
    if brave_api_key is not None:
        overrides["brave_api_key"] = brave_api_key

    if overrides:
        # Settings 객체 복사 및 오버라이드
        current_data = base_settings.model_dump()
        current_data.update(overrides)
        active_settings = Settings(**current_data)
    else:
        active_settings = base_settings

    # 스테이지 정규화 및 토큰 유무에 따른 자동 활성화
    stages_enum = determine_active_stages(stages, active_settings)

    if options is not None:
        scan_options = options
    else:
        scan_options = ScanOptions(
            deep_scan=deep_scan,
            crawl_urls=crawl_urls,
            crawl_max_depth=crawl_max_depth,
        )

    sources = create_sources_for_stages(stages_enum, active_settings)

    all_findings: list[Finding] = []
    errors: list[str] = []

    for source in sources:
        try:
            findings = await source.search_and_match(resolved_spec, scan_options)
            all_findings.extend(findings)
        except Exception as e:
            err_msg = f"[{source.name}] {e}"
            logger.error("Error during scan source %s: %s", source.name, e)
            errors.append(err_msg)

    return build_scan_result(resolved_spec, all_findings, errors, scan_options)


def scan(
    target: KeySpec | str | None = None,
    *,
    key: str | None = None,
    spec: KeySpec | None = None,
    stages: Sequence[Stage | str] | None = None,
    options: ScanOptions | None = None,
    deep_scan: bool = True,
    github_token: str | None = None,
    brave_api_key: str | None = None,
    crawl_urls: list[str] | None = None,
    crawl_max_depth: int = 1,
    settings: Settings | None = None,
    prefix_len: int = 8,
    postfix_len: int = 6,
    name: str | None = None,
) -> ScanResult:
    """동기 방식으로 API 키 노출 여부를 점검합니다.

    일반 CLI 스크립트나 배치 작업에서 간편하게 1줄로 호출할 수 있습니다.
    이미 비동기 이벤트 루프가 실행 중인 환경에서는 `await scan_async(...)`를 사용하세요.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        raise RuntimeError(
            "An asyncio event loop is already running in this thread. "
            "Please use 'await whereismykey.scan_async(...)' instead."
        )

    return asyncio.run(
        scan_async(
            target,
            key=key,
            spec=spec,
            stages=stages,
            options=options,
            deep_scan=deep_scan,
            github_token=github_token,
            brave_api_key=brave_api_key,
            crawl_urls=crawl_urls,
            crawl_max_depth=crawl_max_depth,
            settings=settings,
            prefix_len=prefix_len,
            postfix_len=postfix_len,
            name=name,
        )
    )
