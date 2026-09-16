"""Brave Search API 공급자 구현."""

from __future__ import annotations

import logging

import httpx

from app.sources.web_search.base import WebSearchError, WebSearchProvider, WebSearchResultItem

logger = logging.getLogger(__name__)


class BraveSearchProvider(WebSearchProvider):
    """Brave Search API 공급자."""

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
        return "brave"

    async def search(self, query: str, max_results: int) -> list[WebSearchResultItem]:
        if not self.api_key:
            raise WebSearchError("BRAVE_API_KEY is not configured")

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key,
            "User-Agent": self.user_agent,
        }
        params = {
            "q": query,
            "count": min(max_results, 20),
        }

        client = self._custom_client or httpx.AsyncClient(timeout=10.0)
        should_close = self._custom_client is None

        try:
            resp = await client.get(
                "https://api.search.brave.com/res/v1/web/search",
                headers=headers,
                params=params,
            )
            if resp.status_code != 200:
                raise WebSearchError(
                    f"Brave Search API returned status {resp.status_code}: {resp.text}"
                )

            data = resp.json()
            results = data.get("web", {}).get("results", [])
            items: list[WebSearchResultItem] = []
            for r in results:
                url = r.get("url")
                if url:
                    items.append(
                        WebSearchResultItem(
                            url=url,
                            title=r.get("title", ""),
                            snippet=r.get("description", ""),
                        )
                    )
            return items
        except httpx.RequestError as e:
            raise WebSearchError(f"Network error calling Brave Search API: {e}") from e
        finally:
            if should_close:
                await client.aclose()
