"""스캔 스테이지별 소스 생성 및 매핑."""

from __future__ import annotations

from app.config import Settings
from app.core.models import Stage
from app.sources.base import SearchSource
from app.sources.fetcher import SafeFetcher
from app.sources.github_code import GitHubCodeSource
from app.sources.web import WebSearchSource
from app.sources.web_search import get_web_search_provider


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
    return sources
