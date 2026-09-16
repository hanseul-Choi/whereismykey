"""웹 검색 공급자 및 WebSearchSource 단위 테스트."""

from __future__ import annotations

import httpx
import pytest
import respx
from whereismykey.config import Settings
from whereismykey.core.models import Confidence, Severity, Stage
from whereismykey.sources.base import ScanOptions
from whereismykey.sources.fetcher import SafeFetcher
from whereismykey.sources.web import WebSearchSource
from whereismykey.sources.web_search import (
    BraveSearchProvider,
    GoogleCSESearchProvider,
    SerpAPISearchProvider,
    WebSearchError,
    WebSearchResultItem,
    get_web_search_provider,
)

from tests.conftest import FAKE_KEY


@pytest.mark.asyncio
@respx.mock
async def test_brave_search_provider_success() -> None:
    api_url = "https://api.search.brave.com/res/v1/web/search"
    mock_resp = {
        "web": {
            "results": [
                {
                    "title": "Example Post",
                    "url": "https://example.com/post",
                    "description": "Here is a code snippet",
                }
            ]
        }
    }
    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_resp))

    async with httpx.AsyncClient() as client:
        provider = BraveSearchProvider(api_key="mock_key", client=client)
        results = await provider.search("my-query", 10)
        assert len(results) == 1
        assert results[0].title == "Example Post"
        assert results[0].url == "https://example.com/post"


@pytest.mark.asyncio
async def test_brave_search_provider_missing_key() -> None:
    provider = BraveSearchProvider(api_key=None)
    with pytest.raises(WebSearchError, match="BRAVE_API_KEY is not configured"):
        await provider.search("query", 10)


@pytest.mark.asyncio
@respx.mock
async def test_google_cse_search_provider_success() -> None:
    api_url = "https://www.googleapis.com/customsearch/v1"
    mock_resp = {
        "items": [
            {
                "title": "Google Result",
                "link": "https://google-result.com/article",
                "snippet": "some snippet",
            }
        ]
    }
    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_resp))

    async with httpx.AsyncClient() as client:
        provider = GoogleCSESearchProvider(api_key="key", cx="cx", client=client)
        results = await provider.search("query", 10)
        assert len(results) == 1
        assert results[0].url == "https://google-result.com/article"


@pytest.mark.asyncio
@respx.mock
async def test_serpapi_search_provider_success() -> None:
    api_url = "https://serpapi.com/search"
    mock_resp = {
        "organic_results": [
            {
                "title": "Serp Result",
                "link": "https://serp-result.com/page",
                "snippet": "some serp snippet",
            }
        ]
    }
    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_resp))

    async with httpx.AsyncClient() as client:
        provider = SerpAPISearchProvider(api_key="key", client=client)
        results = await provider.search("query", 10)
        assert len(results) == 1
        assert results[0].url == "https://serp-result.com/page"


def test_get_web_search_provider_factory() -> None:
    s_brave = Settings(web_search_provider="brave", brave_api_key="k")
    assert isinstance(get_web_search_provider(s_brave), BraveSearchProvider)

    s_cse = Settings(web_search_provider="google_cse", google_cse_key="k", google_cse_cx="c")
    assert isinstance(get_web_search_provider(s_cse), GoogleCSESearchProvider)

    s_serp = Settings(web_search_provider="serpapi", serpapi_key="k")
    assert isinstance(get_web_search_provider(s_serp), SerpAPISearchProvider)


class FakeWebProvider:
    name = "fake"

    async def search(self, query: str, max_results: int) -> list[WebSearchResultItem]:
        return [
            WebSearchResultItem(url="https://example.com/leak1", title="Leak 1"),
            WebSearchResultItem(url="https://example.com/safe", title="Safe Page"),
        ]


@pytest.mark.asyncio
@respx.mock
async def test_web_search_source_end_to_end(key_spec_no_length) -> None:
    respx.get("https://example.com/leak1").mock(
        return_value=httpx.Response(
            200,
            text=f"<html><body>Key leaked here: {FAKE_KEY}</body></html>",
            headers={"Content-Type": "text/html"},
        )
    )
    respx.get("https://example.com/safe").mock(
        return_value=httpx.Response(
            200,
            text="<html><body>Nothing here</body></html>",
            headers={"Content-Type": "text/html"},
        )
    )

    async with httpx.AsyncClient() as client:
        fetcher = SafeFetcher(client=client)
        source = WebSearchSource(provider=FakeWebProvider(), fetcher=fetcher)  # type: ignore[arg-type]

        findings = await source.search_and_match(key_spec_no_length, ScanOptions())
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.CONFIRMED
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].stage == Stage.WEB
        assert findings[0].url == "https://example.com/leak1"
