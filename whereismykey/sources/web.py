"""웹 검색 + 페이지 본문 크롤링 소스."""

from __future__ import annotations

import asyncio
import logging

from whereismykey.core.key_spec import KeySpec
from whereismykey.core.matcher import scan_text
from whereismykey.core.models import Finding, Stage, classify
from whereismykey.sources.base import ScanOptions, SearchSource
from whereismykey.sources.fetcher import SafeFetcher
from whereismykey.sources.web_search.base import WebSearchProvider

logger = logging.getLogger(__name__)


class WebSearchSource(SearchSource):
    """웹 검색 공급자로부터 URL 목록을 검색하고, 각 페이지를 가져와 키를 대조."""

    def __init__(
        self,
        provider: WebSearchProvider,
        fetcher: SafeFetcher | None = None,
        *,
        max_concurrent_fetches: int = 8,
    ) -> None:
        self.provider = provider
        self.fetcher = fetcher or SafeFetcher()
        self.max_concurrent_fetches = max_concurrent_fetches

    @property
    def name(self) -> str:
        return f"web_search_{self.provider.name}"

    @property
    def stage(self) -> Stage:
        return Stage.WEB

    async def search_and_match(
        self,
        spec: KeySpec,
        options: ScanOptions,
    ) -> list[Finding]:
        query = f'"{spec.prefix}" "{spec.postfix}"'
        search_items = await self.provider.search(query, options.max_results_per_source)
        if not search_items:
            return []

        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.max_concurrent_fetches)

        async def _fetch_and_scan(url: str) -> list[Finding]:
            async with semaphore:
                try:
                    text = await self.fetcher.fetch_text(url)
                    if not text:
                        return []
                    match_results = scan_text(text, spec)
                    item_findings: list[Finding] = []
                    for mr in match_results:
                        confidence, severity = classify(mr.hash_matched)
                        item_findings.append(
                            Finding(
                                confidence=confidence,
                                severity=severity,
                                stage=Stage.WEB,
                                source=self.name,
                                url=url,
                                snippet=mr.snippet,
                            )
                        )
                    return item_findings
                except Exception as e:
                    logger.debug("Failed to fetch or scan page %s: %s", url, e)
                    return []

        tasks = [_fetch_and_scan(item.url) for item in search_items]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results_list:
            if isinstance(res, list):
                findings.extend(res)

        return findings
