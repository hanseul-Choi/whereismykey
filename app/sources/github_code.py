"""GitHub Code Search API 소스."""

from __future__ import annotations

import asyncio
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

    def build_query(self, spec: KeySpec, options: ScanOptions) -> str:
        """전 세계 수십만 건의 노이즈를 1차 압축하기 위한 결합 쿼리 생성."""
        parts = [f'"{spec.prefix}"', f'"{spec.postfix}"']
        if options.qualifiers:
            parts.extend(options.qualifiers)
        return " ".join(parts)

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

        query = self.build_query(spec, options)
        client = self._custom_client or httpx.AsyncClient(timeout=options.fetch_timeout_s)
        should_close = self._custom_client is None

        findings: list[Finding] = []
        page = 1
        # GitHub Code Search는 최대 1,000건(100건 x 10페이지)까지 지원
        max_pages = 10 if options.deep_scan else 1
        per_page = min(options.max_results_per_source, 100)

        try:
            while page <= max_pages:
                params = {
                    "q": query,
                    "per_page": per_page,
                    "page": page,
                }

                resp = await client.get(
                    "https://api.github.com/search/code",
                    params=params,
                    headers=headers,
                )
                if resp.status_code == 401:
                    raise GitHubSourceError("Invalid or expired GitHub token")
                if resp.status_code in (403, 429):
                    raise GitHubSourceError(
                        f"GitHub API rate limit exceeded or access forbidden: {resp.text}"
                    )
                if resp.status_code != 200:
                    raise GitHubSourceError(
                        f"GitHub search API returned status {resp.status_code}: {resp.text}"
                    )

                data = resp.json()
                items = data.get("items", [])
                total_count = data.get("total_count", 0)

                if not items:
                    break

                for item in items:
                    html_url = item.get("html_url", "")
                    repo_full_name = item.get("repository", {}).get("full_name")
                    path = item.get("path")

                    text_matches = item.get("text_matches", [])
                    for tm in text_matches:
                        fragment = tm.get("fragment", "")
                        if not fragment:
                            continue
                        match_results = scan_text(fragment, spec)
                        for mr in match_results:
                            confidence, severity = classify(mr.hash_matched)
                            start_idx = mr.candidate.span[0]
                            line_count = fragment[:start_idx].count("\n") + 1
                            finding_url = (
                                f"{html_url}#L{line_count}" if html_url and line_count else html_url
                            )

                            findings.append(
                                Finding(
                                    confidence=confidence,
                                    severity=severity,
                                    stage=Stage.GITHUB,
                                    source=self.name,
                                    url=finding_url,
                                    repo=repo_full_name,
                                    path=path,
                                    line=line_count,
                                    snippet=mr.snippet,
                                )
                            )

                # 종료 조건 검사
                if not options.deep_scan:
                    break
                if len(findings) >= options.max_results_per_source:
                    break
                if page * per_page >= total_count or len(items) < per_page:
                    break

                page += 1
                # 레이트 리밋 방어를 위한 미세 딜레이
                await asyncio.sleep(0.1)

            return findings
        except httpx.RequestError as e:
            raise GitHubSourceError(f"Network error while connecting to GitHub: {e}") from e
        finally:
            if should_close:
                await client.aclose()
