"""GitHub Code Search 소스 단위 테스트."""

from __future__ import annotations

import httpx
import pytest
import respx
from app.core.models import Confidence, Severity, Stage
from app.sources.base import ScanOptions
from app.sources.github_code import GitHubCodeSource, GitHubSourceError

from tests.conftest import FAKE_KEY, FAKE_PREFIX


@pytest.mark.asyncio
async def test_github_source_requires_token(key_spec_no_length) -> None:
    source = GitHubCodeSource(token=None)
    with pytest.raises(GitHubSourceError, match="GITHUB_TOKEN is not configured"):
        await source.search_and_match(key_spec_no_length, ScanOptions())


@pytest.mark.asyncio
@respx.mock
async def test_github_source_success_matching(key_spec_no_length) -> None:
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

    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_response))

    async with httpx.AsyncClient() as client:
        source = GitHubCodeSource(token=token, client=client)
        findings = await source.search_and_match(key_spec_no_length, ScanOptions())

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
        assert FAKE_KEY not in finding.snippet  # 마스킹 확인


@pytest.mark.asyncio
@respx.mock
async def test_github_source_pattern_only_match(key_spec_no_length) -> None:
    api_url = "https://api.github.com/search/code"
    token = "ghp_mock_token_123"

    pattern_only_key = f"{FAKE_PREFIX}DifferentMiddleParta1b2c3d"

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
