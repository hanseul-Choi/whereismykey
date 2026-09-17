import logging
from collections.abc import Sequence

from whereismykey.config import Settings
from whereismykey.core.models import Stage
from whereismykey.sources.base import SearchSource
from whereismykey.sources.crawl import WebCrawlSource
from whereismykey.sources.fetcher import SafeFetcher
from whereismykey.sources.github_code import GitHubCodeSource
from whereismykey.sources.web import WebSearchSource
from whereismykey.sources.web_search import get_web_search_provider

logger = logging.getLogger(__name__)


def determine_active_stages(
    requested_stages: Sequence[Stage | str] | None,
    settings: Settings,
) -> list[Stage]:
    """요청된 스테이지 목록을 정규화하거나, 미지정 시 설정된 토큰에 맞춰 자동 결정."""
    if requested_stages is not None:
        return [Stage(s) if isinstance(s, str) else s for s in requested_stages]

    active: list[Stage] = []
    if settings.github_token:
        active.append(Stage.GITHUB)
    if (
        settings.brave_api_key
        or (settings.google_cse_key and settings.google_cse_cx)
        or settings.serpapi_key
    ):
        active.append(Stage.WEB)

    # 크롤러(Crawl)는 API 키가 필요 없으므로 항상 기본 활성화
    active.append(Stage.CRAWL)
    return active


def create_sources_for_stages(
    stages: list[Stage],
    settings: Settings,
    *,
    skip_missing_tokens: bool = True,
) -> list[SearchSource]:
    """요청된 스테이지 목록에 맞춰 검색 소스 객체들을 생성."""
    sources: list[SearchSource] = []
    for stage in stages:
        if stage == Stage.GITHUB:
            if not settings.github_token and skip_missing_tokens and len(stages) > 1:
                logger.info("GITHUB_TOKEN 미설정으로 Stage.GITHUB 소스를 건너뜁니다.")
                continue

            sources.append(
                GitHubCodeSource(
                    token=settings.github_token,
                    user_agent=settings.http_user_agent,
                )
            )
        elif stage == Stage.WEB:
            has_web_key = bool(
                settings.brave_api_key
                or (settings.google_cse_key and settings.google_cse_cx)
                or settings.serpapi_key
            )
            if not has_web_key and skip_missing_tokens and len(stages) > 1:
                logger.info("웹 검색 키 미설정으로 다중 스테이지 중 Stage.WEB 소스를 건너뜁니다.")
                continue
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
