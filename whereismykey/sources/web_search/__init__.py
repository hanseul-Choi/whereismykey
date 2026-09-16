"""웹 검색 공급자 패키지 및 팩토리."""

from __future__ import annotations

from whereismykey.config import Settings
from whereismykey.sources.web_search.base import (
    WebSearchError,
    WebSearchProvider,
    WebSearchResultItem,
)
from whereismykey.sources.web_search.brave import BraveSearchProvider
from whereismykey.sources.web_search.google_cse import GoogleCSESearchProvider
from whereismykey.sources.web_search.serpapi import SerpAPISearchProvider


def get_web_search_provider(settings: Settings) -> WebSearchProvider:
    """설정에 지정된 웹 검색 공급자 인스턴스를 반환."""
    provider_name = settings.web_search_provider.lower()
    if provider_name == "brave":
        return BraveSearchProvider(
            api_key=settings.brave_api_key,
            user_agent=settings.http_user_agent,
        )
    if provider_name == "google_cse":
        return GoogleCSESearchProvider(
            api_key=settings.google_cse_key,
            cx=settings.google_cse_cx,
            user_agent=settings.http_user_agent,
        )
    if provider_name == "serpapi":
        return SerpAPISearchProvider(
            api_key=settings.serpapi_key,
            user_agent=settings.http_user_agent,
        )
    raise WebSearchError(f"Unsupported web search provider: {settings.web_search_provider}")


__all__ = [
    "BraveSearchProvider",
    "GoogleCSESearchProvider",
    "SerpAPISearchProvider",
    "WebSearchError",
    "WebSearchProvider",
    "WebSearchResultItem",
    "get_web_search_provider",
]
