"""GitHub Code Search 소스 단위 테스트."""

from __future__ import annotations

import httpx
import pytest
import respx
from whereismykey.core.models import Confidence, Severity, Stage
from whereismykey.sources.base import ScanOptions
from whereismykey.sources.github_code import GitHubCodeSource, GitHubSourceError

from tests.conftest import FAKE_KEY, FAKE_POSTFIX, FAKE_PREFIX


@pytest.mark.asyncio
async def test_github_source_requires_token(key_spec_no_length) -> None:
    source = GitHubCodeSource(token=None)
    with pytest.raises(GitHubSourceError, match="GITHUB_TOKEN is not configured"):
        await source.search_and_match(key_spec_no_length, ScanOptions())


@pytest.mark.asyncio
@respx.mock
async def test_github_source_success_matching_with_combined_query(key_spec_no_length) -> None:
    api_url = "https://api.github.com/search/code"
    token = "ghp_mock_token_123"

    mock_response = {
        "total_count": 1,
        "items": [
            {
                "name": "config.py",
                "path": "src/config.py",
                "html_url": "https://github.com/owner/repo/blob/main/src/config.py",
                "repository": {"full_name": "owner/repo"},
                "text_matches": [
                    {
                        "fragment": f'# comment\nSECRET_KEY = "{FAKE_KEY}"\nprint("ok")',
                        "matches": [{"text": FAKE_KEY, "indices": [23, 23 + len(FAKE_KEY)]}],
                    }
                ],
            }
        ],
    }

    # 결합 쿼리 ("prefix" "postfix") 확인
    route = respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_response))

    async with httpx.AsyncClient() as client:
        source = GitHubCodeSource(token=token, client=client)
        findings = await source.search_and_match(key_spec_no_length, ScanOptions())

        assert route.called
        request_params = route.calls.last.request.url.params
        assert request_params["q"] == f'"{FAKE_PREFIX}" "{FAKE_POSTFIX}"'

        assert len(findings) == 1
        finding = findings[0]
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.severity == Severity.CRITICAL
        assert finding.stage == Stage.GITHUB
        assert finding.source == "github_code_search"
        assert finding.repo == "owner/repo"
        assert finding.path == "src/config.py"
        assert finding.line == 2
        assert finding.url == "https://github.com/owner/repo/blob/main/src/config.py#L2"
        assert FAKE_PREFIX in finding.snippet
        assert FAKE_KEY not in finding.snippet


@pytest.mark.asyncio
@respx.mock
async def test_github_source_qualifiers_in_query(key_spec_no_length) -> None:
    api_url = "https://api.github.com/search/code"
    token = "ghp_mock_token_123"

    mock_response = {"total_count": 0, "items": []}
    route = respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_response))

    async with httpx.AsyncClient() as client:
        source = GitHubCodeSource(token=token, client=client)
        options = ScanOptions(qualifiers=["org:acme", "filename:.env"])
        await source.search_and_match(key_spec_no_length, options)

        request_params = route.calls.last.request.url.params
        assert request_params["q"] == f'"{FAKE_PREFIX}" "{FAKE_POSTFIX}" org:acme filename:.env'


@pytest.mark.asyncio
@respx.mock
async def test_github_source_deep_scan_pagination(key_spec_no_length) -> None:
    api_url = "https://api.github.com/search/code"
    token = "ghp_mock_token_123"

    # 1페이지 응답 (100개 반환)
    resp_page1 = {
        "total_count": 101,
        "items": [
            {
                "html_url": "https://github.com/repo1/file.py",
                "repository": {"full_name": "repo1"},
                "path": "file.py",
                "text_matches": [{"fragment": f"KEY = {FAKE_KEY}"}],
            }
        ]
        * 100,
    }
    # 2페이지 응답 (남은 1개 반환)
    resp_page2 = {
        "total_count": 101,
        "items": [
            {
                "html_url": "https://github.com/repo2/file.py",
                "repository": {"full_name": "repo2"},
                "path": "file.py",
                "text_matches": [{"fragment": f"KEY = {FAKE_KEY}"}],
            }
        ],
    }

    route1 = respx.get(api_url, params={"page": "1"}).mock(
        return_value=httpx.Response(200, json=resp_page1)
    )
    route2 = respx.get(api_url, params={"page": "2"}).mock(
        return_value=httpx.Response(200, json=resp_page2)
    )

    async with httpx.AsyncClient() as client:
        source = GitHubCodeSource(token=token, client=client)
        options = ScanOptions(deep_scan=True, max_results_per_source=200)
        findings = await source.search_and_match(key_spec_no_length, options)

        assert route1.called
        assert route2.called
        assert len(findings) == 101
        assert findings[0].repo == "repo1"
        assert findings[-1].repo == "repo2"


@pytest.mark.asyncio
@respx.mock
async def test_github_source_pattern_only_match(key_spec_no_length) -> None:
    api_url = "https://api.github.com/search/code"
    token = "ghp_mock_token_123"

    pattern_only_key = f"{FAKE_PREFIX}DifferentMiddlePart{FAKE_POSTFIX}"

    mock_response = {
        "total_count": 1,
        "items": [
            {
                "name": "test.txt",
                "path": "test.txt",
                "html_url": "https://github.com/owner/repo/blob/main/test.txt",
                "repository": {"full_name": "owner/repo"},
                "text_matches": [
                    {
                        "fragment": f"sample token: {pattern_only_key}",
                        "matches": [],
                    }
                ],
            }
        ],
    }

    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_response))

    async with httpx.AsyncClient() as client:
        source = GitHubCodeSource(token=token, client=client)
        findings = await source.search_and_match(key_spec_no_length, ScanOptions())

        assert len(findings) == 1
        assert findings[0].confidence == Confidence.PATTERN_ONLY
        assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
@respx.mock
async def test_github_source_rate_limited(key_spec_no_length) -> None:
    api_url = "https://api.github.com/search/code"
    token = "ghp_mock_token_123"

    respx.get(api_url).mock(return_value=httpx.Response(403, text="rate limit exceeded"))

    async with httpx.AsyncClient() as client:
        source = GitHubCodeSource(token=token, client=client)
        with pytest.raises(GitHubSourceError, match="rate limit exceeded"):
            await source.search_and_match(key_spec_no_length, ScanOptions())
