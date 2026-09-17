"""스캔 스테이지별 소스 생성 및 매핑."""

from __future__ import annotations

from whereismykey.config import Settings
from whereismykey.core.models import Stage
from whereismykey.sources.base import SearchSource
from whereismykey.sources.crawl import WebCrawlSource
from whereismykey.sources.fetcher import SafeFetcher
from whereismykey.sources.github_code import GitHubCodeSource
from whereismykey.sources.web import WebSearchSource
from whereismykey.sources.web_search import get_web_search_provider


def create_sources_for_stages(
    stages: list[Stage],
    settings: Settings,
) -> list[SearchSource]:
    """요청된 스테이지 목록에 맞춰 검색 소스 객체들을 생성."""
    sources: list[SearchSource] = []
    for stage in stages:
        if stage == Stage.GITHUB:
            sources.append(
                GitHubCodeSource(
                    token=settings.github_token,
                    user_agent=settings.http_user_agent,
                )
            )
        elif stage == Stage.WEB:
            provider = get_web_search_provider(settings)
            fetcher = SafeFetcher(
                user_agent=settings.http_user_agent,
                timeout_s=settings.fetch_timeout_s,
            )
            sources.append(
                WebSearchSource(
                    provider=provider,
                    fetcher=fetcher,
                    max_concurrent_fetches=settings.max_concurrent_fetches,
                )
            )
        elif stage == Stage.CRAWL:
            fetcher = SafeFetcher(
                user_agent=settings.http_user_agent,
                timeout_s=settings.fetch_timeout_s,
            )
            sources.append(
                WebCrawlSource(
                    fetcher=fetcher,
                    max_concurrent_fetches=settings.max_concurrent_fetches,
                    user_agent=settings.http_user_agent,
                    timeout_s=settings.fetch_timeout_s,
                )
            )
    return sources
