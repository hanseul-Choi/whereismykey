"""웹 검색 공급자 추상 인터페이스."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class WebSearchError(Exception):
    """웹 검색 API 호출 실패."""


@dataclass(frozen=True)
class WebSearchResultItem:
    """웹 검색 결과 항목."""

    url: str
    title: str = ""
    snippet: str = ""


class WebSearchProvider(ABC):
    """웹 검색 API 공급자 인터페이스."""

    @property
    @abstractmethod
    def name(self) -> str:
        """공급자 이름 (예: 'brave', 'google_cse', 'serpapi')."""

    @abstractmethod
    async def search(self, query: str, max_results: int) -> list[WebSearchResultItem]:
        """검색 쿼리를 실행하여 결과 항목 목록을 반환한다."""
