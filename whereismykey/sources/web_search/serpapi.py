"""SerpAPI 공급자 구현."""

from __future__ import annotations

import logging

import httpx

from whereismykey.sources.web_search.base import (
    WebSearchError,
    WebSearchProvider,
    WebSearchResultItem,
)

logger = logging.getLogger(__name__)


class SerpAPISearchProvider(WebSearchProvider):
    """SerpAPI (Google 검색 엔진) 공급자."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        user_agent: str = "whereismykey/0.1 (+security-scan)",
    ) -> None:
        self.api_key = api_key
        self.user_agent = user_agent
        self._custom_client = client

    @property
    def name(self) -> str:
        return "serpapi"

    async def search(self, query: str, max_results: int) -> list[WebSearchResultItem]:
        if not self.api_key:
            raise WebSearchError("SERPAPI_KEY is not configured")

        headers = {"User-Agent": self.user_agent}
        params = {
            "api_key": self.api_key,
            "engine": "google",
            "q": query,
            "num": min(max_results, 10),
        }

        client = self._custom_client or httpx.AsyncClient(timeout=10.0)
        should_close = self._custom_client is None

        try:
            resp = await client.get(
                "https://serpapi.com/search",
                headers=headers,
                params=params,
            )
            if resp.status_code != 200:
                raise WebSearchError(f"SerpAPI returned status {resp.status_code}: {resp.text}")

            data = resp.json()
            results = data.get("organic_results", [])
            items: list[WebSearchResultItem] = []
            for r in results:
                link = r.get("link")
                if link:
                    items.append(
                        WebSearchResultItem(
                            url=link,
                            title=r.get("title", ""),
                            snippet=r.get("snippet", ""),
                        )
                    )
            return items
        except httpx.RequestError as e:
            raise WebSearchError(f"Network error calling SerpAPI: {e}") from e
        finally:
            if should_close:
                await client.aclose()
