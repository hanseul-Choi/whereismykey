"""웹 크롤링(Web Crawling) 기반 키 노출 탐색 소스.

별도의 외부 검색 API 키(Brave, Google 등) 없이 공개 검색 엔진 HTML 크롤링 및
지정된 시드 URL을 크롤링하여 노출된 키를 탐색합니다.
"""

from __future__ import annotations

import asyncio
import logging
import urllib.parse
from typing import Any

import httpx
from selectolax.parser import HTMLParser

from whereismykey.core.key_spec import KeySpec
from whereismykey.core.matcher import scan_text
from whereismykey.core.models import Finding, Stage, classify
from whereismykey.sources.base import ScanOptions, SearchSource
from whereismykey.sources.fetcher import SafeFetcher

logger = logging.getLogger(__name__)

DDG_SEARCH_URL = "https://html.duckduckgo.com/html/"
DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


class WebCrawlSource(SearchSource):
    """API 키 없이 공개 웹 검색 엔진 크롤링 및 시드 URL 탐색을 수행하는 크롤러 소스."""

    def __init__(
        self,
        fetcher: SafeFetcher | None = None,
        *,
        max_concurrent_fetches: int = 8,
        user_agent: str | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self.fetcher = fetcher or SafeFetcher(user_agent=user_agent or DEFAULT_BROWSER_UA)
        self.max_concurrent_fetches = max_concurrent_fetches
        self.user_agent = user_agent or DEFAULT_BROWSER_UA
        self.timeout_s = timeout_s

    @property
    def name(self) -> str:
        return "web_crawler"

    @property
    def stage(self) -> Stage:
        return Stage.CRAWL

    def _extract_target_url(self, raw_href: str) -> str | None:
        """DuckDuckGo 리다이렉트 링크나 일반 링크에서 실제 목적지 URL을 추출."""
        if not raw_href:
            return None

        # //duckduckgo.com/l/?uddg=https%3A%2F%2F... 형태 처리
        if "uddg=" in raw_href:
            parsed = urllib.parse.urlparse(raw_href)
            qs = urllib.parse.parse_qs(parsed.query)
            uddg_vals = qs.get("uddg")
            if uddg_vals:
                return uddg_vals[0]

        if raw_href.startswith("//"):
            return "https:" + raw_href
        if raw_href.startswith("http://") or raw_href.startswith("https://"):
            return raw_href

        return None

    async def _search_engine_crawl(self, query: str, limit: int) -> list[str]:
        """DuckDuckGo HTML 검색을 통해 후보 웹페이지 URL 목록을 수집."""
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ko;q=0.8",
        }
        data = {"q": query}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s,
                headers=headers,
                follow_redirects=True,
            ) as client:
                resp = await client.post(DDG_SEARCH_URL, data=data)
                if resp.status_code != 200:
                    logger.warning(
                        "DuckDuckGo HTML crawl returned status %s: %s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return []

                html = resp.text
        except Exception as e:
            logger.error("Failed to crawl search engine %s: %s", DDG_SEARCH_URL, e)
            return []

        urls: list[str] = []
        tree = HTMLParser(html)
        for node in tree.css(".result"):
            title_a = node.css_first(".result__title a") or node.css_first("a.result__url")
            if not title_a:
                continue

            raw_href = title_a.attributes.get("href") or ""
            target_url = self._extract_target_url(raw_href)
            if target_url and target_url not in urls:
                urls.append(target_url)
                if len(urls) >= limit:
                    break

        return urls

    async def search_and_match(
        self,
        spec: KeySpec,
        options: ScanOptions,
    ) -> list[Finding]:
        query = f'"{spec.prefix}" "{spec.postfix}"'
        limit = options.max_results_per_source

        # 1. 검색 엔진 크롤링을 통한 URL 수집
        crawl_target_urls = await self._search_engine_crawl(query, limit)

        # 2. 사용자가 직접 지정한 시드 URL 추가 (있는 경우)
        if options.crawl_urls:
            for u in options.crawl_urls:
                if u not in crawl_target_urls:
                    crawl_target_urls.append(u)

        if not crawl_target_urls:
            return []

        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.max_concurrent_fetches)
        scanned_urls: set[str] = set()

        async def _fetch_and_scan(url: str, is_seed: bool = False) -> list[Finding]:
            if url in scanned_urls:
                return []
            scanned_urls.add(url)

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
                                stage=Stage.CRAWL,
                                source=self.name,
                                url=url,
                                snippet=mr.snippet,
                            )
                        )

                    # 시드 URL이고 탐색 깊이 옵션이 있는 경우 내부 링크 크롤링 (depth 1)
                    if is_seed and options.crawl_max_depth > 0:
                        child_urls = self._extract_internal_links(url, text)
                        for child_url in child_urls[:10]:  # 페이지당 최대 10개 내부 링크
                            child_findings = await _fetch_and_scan(child_url, is_seed=False)
                            item_findings.extend(child_findings)

                    return item_findings
                except Exception as e:
                    logger.debug("Failed to fetch or scan page %s: %s", url, e)
                    return []

        tasks = [
            _fetch_and_scan(
                url,
                is_seed=(options.crawl_urls is not None and url in options.crawl_urls),
            )
            for url in crawl_target_urls
        ]
        results_list: list[Any] = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results_list:
            if isinstance(res, list):
                findings.extend(res)

        return findings

    def _extract_internal_links(self, base_url: str, html_text: str) -> list[str]:
        """시드 URL의 내부 동일 도메인 링크들을 추출."""
        parsed_base = urllib.parse.urlparse(base_url)
        base_domain = parsed_base.netloc
        if not base_domain:
            return []

        try:
            tree = HTMLParser(html_text)
            links: list[str] = []
            for a in tree.css("a"):
                href = a.attributes.get("href")
                if not href:
                    continue
                joined = urllib.parse.urljoin(base_url, href)
                parsed_joined = urllib.parse.urlparse(joined)
                if (
                    parsed_joined.scheme in ("http", "https")
                    and parsed_joined.netloc == base_domain
                ):
                    clean_url = urllib.parse.urldefrag(joined)[0]
                    if clean_url not in links and clean_url != base_url:
                        links.append(clean_url)
            return links
        except Exception:
            return []
