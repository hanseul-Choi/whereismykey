"""Google Custom Search JSON API 공급자 구현."""

from __future__ import annotations

import logging

import httpx

from whereismykey.sources.web_search.base import (
    WebSearchError,
    WebSearchProvider,
    WebSearchResultItem,
)

logger = logging.getLogger(__name__)


class GoogleCSESearchProvider(WebSearchProvider):
    """Google Custom Search Engine 공급자."""

    def __init__(
        self,
        api_key: str | None = None,
        cx: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        user_agent: str = "whereismykey/0.1 (+security-scan)",
    ) -> None:
        self.api_key = api_key
        self.cx = cx
        self.user_agent = user_agent
        self._custom_client = client

    @property
    def name(self) -> str:
        return "google_cse"

    async def search(self, query: str, max_results: int) -> list[WebSearchResultItem]:
        if not self.api_key or not self.cx:
            raise WebSearchError("GOOGLE_CSE_KEY and GOOGLE_CSE_CX must be configured")

        headers = {"User-Agent": self.user_agent}
        params = {
            "key": self.api_key,
            "cx": self.cx,
            "q": query,
            "num": min(max_results, 10),
        }

        client = self._custom_client or httpx.AsyncClient(timeout=10.0)
        should_close = self._custom_client is None

        try:
            resp = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                headers=headers,
                params=params,
            )
            if resp.status_code != 200:
                raise WebSearchError(
                    f"Google CSE API returned status {resp.status_code}: {resp.text}"
                )

            data = resp.json()
            items_data = data.get("items", [])
            items: list[WebSearchResultItem] = []
            for r in items_data:
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
            raise WebSearchError(f"Network error calling Google CSE API: {e}") from e
        finally:
            if should_close:
                await client.aclose()
