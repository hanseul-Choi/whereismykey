"""GitHub Code Search API 소스."""

from __future__ import annotations

import logging

import httpx

from app.core.key_spec import KeySpec
from app.core.matcher import scan_text
from app.core.models import Finding, Stage, classify
from app.sources.base import ScanOptions, SearchSource

logger = logging.getLogger(__name__)


class GitHubSourceError(Exception):
    """GitHub 소스 연동 에러."""


class GitHubCodeSource(SearchSource):
    """GitHub Code Search API를 이용해 공개 저장소의 코드를 검색하고 키를 대조."""

    def __init__(
        self,
        token: str | None = None,
        *,
        user_agent: str = "whereismykey/0.1 (+security-scan)",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.token = token
        self.user_agent = user_agent
        self._custom_client = client

    @property
    def name(self) -> str:
        return "github_code_search"

    @property
    def stage(self) -> Stage:
        return Stage.GITHUB

    async def search_and_match(
        self,
        spec: KeySpec,
        options: ScanOptions,
    ) -> list[Finding]:
        if not self.token:
            raise GitHubSourceError("GITHUB_TOKEN is not configured")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": self.user_agent,
        }

        # 검색 쿼리: prefix 검색
        query = f'"{spec.prefix}"'
        params = {
            "q": query,
            "per_page": min(options.max_results_per_source, 100),
        }

        client = self._custom_client or httpx.AsyncClient(timeout=options.fetch_timeout_s)
        should_close = self._custom_client is None

        try:
            resp = await client.get(
                "https://api.github.com/search/code",
                params=params,
                headers=headers,
            )
            if resp.status_code == 401:
                raise GitHubSourceError("Invalid or expired GitHub token")
            if resp.status_code == 403:
                raise GitHubSourceError(
                    f"GitHub API rate limit exceeded or access forbidden: {resp.text}"
                )
            if resp.status_code != 200:
                raise GitHubSourceError(
                    f"GitHub search API returned status {resp.status_code}: {resp.text}"
                )

            data = resp.json()
            items = data.get("items", [])
            findings: list[Finding] = []

            for item in items:
                html_url = item.get("html_url", "")
                repo_full_name = item.get("repository", {}).get("full_name")
                path = item.get("path")

                # text_matches 확인
                text_matches = item.get("text_matches", [])
                if text_matches:
                    for tm in text_matches:
                        fragment = tm.get("fragment", "")
                        if not fragment:
                            continue
                        match_results = scan_text(fragment, spec)
                        for mr in match_results:
                            confidence, severity = classify(mr.hash_matched)
                            # 줄 번호 추정 (fragment 내 매치 시작 위치 기반)
                            line = None
                            start_idx = mr.candidate.span[0]
                            line_count = fragment[:start_idx].count("\n") + 1
                            line = line_count

                            # URL에 라인 앵커 추가 (#L12)
                            finding_url = f"{html_url}#L{line}" if html_url and line else html_url

                            findings.append(
                                Finding(
                                    confidence=confidence,
                                    severity=severity,
                                    stage=Stage.GITHUB,
                                    source=self.name,
                                    url=finding_url,
                                    repo=repo_full_name,
                                    path=path,
                                    line=line,
                                    snippet=mr.snippet,
                                )
                            )
                else:
                    # text_matches가 없는 경우 스니펫 없이 기본 정보만 확인하거나
                    # raw content가 제공될 경우 처리 가능
                    pass

            return findings
        except httpx.RequestError as e:
            raise GitHubSourceError(f"Network error while connecting to GitHub: {e}") from e
        finally:
            if should_close:
                await client.aclose()
