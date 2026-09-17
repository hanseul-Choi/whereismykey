"""검색 소스 추상 기본 클래스 및 스캔 옵션."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from whereismykey.core.key_spec import KeySpec
from whereismykey.core.models import Finding, Stage


@dataclass(frozen=True)
class ScanOptions:
    """스캔 실행 세부 옵션."""

    max_results_per_source: int = 100
    include_pattern_only: bool = True
    fetch_timeout_s: float = 10.0
    deep_scan: bool = True
    qualifiers: list[str] | None = None
    crawl_urls: list[str] | None = None
    crawl_max_depth: int = 1


class SearchSource(ABC):
    """외부 검색 소스 (GitHub, 웹 등) 인터페이스."""

    @property
    @abstractmethod
    def name(self) -> str:
        """소스 식별 이름 (예: 'github_code_search', 'brave_search')."""

    @property
    @abstractmethod
    def stage(self) -> Stage:
        """속한 스테이지 (Stage.GITHUB / Stage.WEB)."""

    @abstractmethod
    async def search_and_match(
        self,
        spec: KeySpec,
        options: ScanOptions,
    ) -> list[Finding]:
        """소스를 검색하고 매처를 거쳐 발견된 Findings 목록을 반환한다."""
