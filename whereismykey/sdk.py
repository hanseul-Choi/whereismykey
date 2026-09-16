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
from whereismykey.scanner.stages import create_sources_for_stages
from whereismykey.sources.base import ScanOptions

logger = logging.getLogger(__name__)


async def scan_async(
    spec: KeySpec,
    *,
    stages: Sequence[Stage | str] | None = None,
    options: ScanOptions | None = None,
    github_token: str | None = None,
    brave_api_key: str | None = None,
    settings: Settings | None = None,
) -> ScanResult:
    """비동기 방식으로 API 키 노출 여부를 점검합니다.

    Args:
        spec: 점검 대상 KeySpec 객체 (prefix, postfix, sha256 필수).
        stages: 점검할 스테이지 목록 (기본: ["github", "web"]).
        options: 스캔 세부 옵션 (기본: ScanOptions()).
        github_token: GitHub Code Search API 인증 토큰 (설정 파일보다 우선).
        brave_api_key: Brave Search API 인증 키 (설정 파일보다 우선).
        settings: 사용자 정의 Settings 객체 (선택).

    Returns:
        ScanResult: 판정(verdict), 발견 항목(findings), 권고사항, 삭제 템플릿 등.
    """
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

    # 스테이지 정규화
    if stages is None:
        stages_enum = [Stage.GITHUB, Stage.WEB]
    else:
        stages_enum = [Stage(s) if isinstance(s, str) else s for s in stages]

    scan_options = options or ScanOptions()
    sources = create_sources_for_stages(stages_enum, active_settings)

    all_findings: list[Finding] = []
    errors: list[str] = []

    for source in sources:
        try:
            findings = await source.search_and_match(spec, scan_options)
            all_findings.extend(findings)
        except Exception as e:
            err_msg = f"[{source.name}] {e}"
            logger.error("Error during scan source %s: %s", source.name, e)
            errors.append(err_msg)

    return build_scan_result(spec, all_findings, errors, scan_options)


def scan(
    spec: KeySpec,
    *,
    stages: Sequence[Stage | str] | None = None,
    options: ScanOptions | None = None,
    github_token: str | None = None,
    brave_api_key: str | None = None,
    settings: Settings | None = None,
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
            spec,
            stages=stages,
            options=options,
            github_token=github_token,
            brave_api_key=brave_api_key,
            settings=settings,
        )
    )
