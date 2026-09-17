"""whereismykey Python SDK 단위 테스트."""

from __future__ import annotations

import httpx
import pytest
import respx
import whereismykey as wmk
from whereismykey.sources.crawl import DDG_SEARCH_URL

from tests.conftest import FAKE_KEY, FAKE_POSTFIX, FAKE_PREFIX, FAKE_SHA256


def test_sdk_public_exports() -> None:
    """최상위 모듈에서 주요 클래스 및 함수들이 정상적으로 export되는지 검증."""
    assert hasattr(wmk, "KeySpec")
    assert hasattr(wmk, "ScanOptions")
    assert hasattr(wmk, "scan")
    assert hasattr(wmk, "scan_async")
    assert hasattr(wmk, "Verdict")
    assert hasattr(wmk, "Finding")
    assert hasattr(wmk, "ScanResult")
    assert hasattr(wmk, "redact_key")
    assert hasattr(wmk, "__version__")
    assert wmk.__version__ == "0.1.0"


@pytest.mark.asyncio
@respx.mock
async def test_scan_async_success() -> None:
    """scan_async 비동기 호출 검증."""
    api_url = "https://api.github.com/search/code"
    token = "ghp_sdk_token_123"

    mock_resp = {
        "total_count": 1,
        "items": [
            {
                "html_url": "https://github.com/org/repo/blob/main/key.py",
                "repository": {"full_name": "org/repo"},
                "path": "key.py",
                "text_matches": [
                    {
                        "fragment": f'API_KEY = "{FAKE_KEY}"',
                    }
                ],
            }
        ],
    }
    route = respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_resp))

    spec = wmk.KeySpec(
        prefix=FAKE_PREFIX,
        postfix=FAKE_POSTFIX,
        sha256=FAKE_SHA256,
        name="test-sdk-key",
    )

    result = await wmk.scan_async(
        spec,
        stages=[wmk.Stage.GITHUB],
        github_token=token,
    )

    assert route.called
    assert result.verdict == wmk.Verdict.EXPOSED
    assert result.key_name == "test-sdk-key"
    assert result.key_redacted == f"{FAKE_PREFIX}…{FAKE_POSTFIX}"
    assert len(result.findings) == 1
    assert result.findings[0].confidence == wmk.Confidence.CONFIRMED
    assert len(result.recommendations) > 0
    assert "https://github.com/org/repo/blob/main/key.py" in result.takedown_message_template


@respx.mock
def test_scan_sync_success() -> None:
    """scan 동기 호출 검증."""
    api_url = "https://api.github.com/search/code"
    token = "ghp_sync_token_456"

    mock_resp = {
        "total_count": 0,
        "items": [],
    }
    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_resp))

    spec = wmk.KeySpec(
        prefix=FAKE_PREFIX,
        postfix=FAKE_POSTFIX,
        sha256=FAKE_SHA256,
        name="test-safe-key",
    )

    # 동기 함수 호출
    result = wmk.scan(
        spec,
        stages=["github"],
        github_token=token,
    )

    assert result.verdict == wmk.Verdict.NOT_FOUND
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_scan_sync_in_running_loop_raises() -> None:
    """비동기 루프 내에서 동기 scan() 호출 시 적절한 안내와 함께 에러 발생 검증."""
    spec = wmk.KeySpec(
        prefix=FAKE_PREFIX,
        postfix=FAKE_POSTFIX,
        sha256=FAKE_SHA256,
    )

    with pytest.raises(RuntimeError, match=r"Please use 'await whereismykey\.scan_async"):
        wmk.scan(spec)


@respx.mock
def test_scan_with_raw_key_string() -> None:
    """raw key 문자열로 직접 scan() 호출 검증."""
    api_url = "https://api.github.com/search/code"
    token = "ghp_sync_token_789"

    mock_resp = {
        "total_count": 0,
        "items": [],
    }
    respx.get(api_url).mock(return_value=httpx.Response(200, json=mock_resp))

    result = wmk.scan(
        key=FAKE_KEY,
        prefix_len=len(FAKE_PREFIX),
        postfix_len=len(FAKE_POSTFIX),
        stages=["github"],
        github_token=token,
    )
    assert result.verdict == wmk.Verdict.NOT_FOUND
    assert result.key_redacted == f"{FAKE_PREFIX}…{FAKE_POSTFIX}"


@pytest.mark.asyncio
@respx.mock
async def test_scan_async_with_all_three_stages() -> None:
    """GitHub, Web Search, Web Crawl 3대 탐색 방식 동시 실행 검증."""
    # 1. GitHub Code Search mock
    respx.get("https://api.github.com/search/code").mock(
        return_value=httpx.Response(200, json={"total_count": 0, "items": []})
    )
    # 2. Brave Search mock
    respx.get("https://api.search.brave.com/res/v1/web/search").mock(
        return_value=httpx.Response(200, json={"web": {"results": []}})
    )
    # 3. DuckDuckGo HTML Crawl mock
    respx.post(DDG_SEARCH_URL).mock(
        return_value=httpx.Response(200, text="<html><body>No keys found</body></html>")
    )

    result = await wmk.scan_async(
        key=FAKE_KEY,
        stages=["github", "web", "crawl"],
        github_token="ghp_test_all_three",
        brave_api_key="brave_test_all_three",
    )
    assert result.verdict == wmk.Verdict.NOT_FOUND


@pytest.mark.asyncio
@respx.mock
async def test_scan_async_with_crawl_only_without_keys() -> None:
    """외부 API 토큰 없이 순수 Web Crawling 모드로만 실행 검증."""
    # DuckDuckGo HTML Crawl mock
    respx.post(DDG_SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            text='<div class="result"><h2 class="result__title"><a href="https://target.com/page">Link</a></h2></div>',
        )
    )
    # Target page contains secret
    respx.get("https://target.com/page").mock(
        return_value=httpx.Response(200, text=f"Exposed key here: {FAKE_KEY}")
    )

    # API 토큰 전혀 없이 crawl 모드만 실행
    result = await wmk.scan_async(
        key=FAKE_KEY,
        stages=["crawl"],
    )
    assert result.verdict == wmk.Verdict.EXPOSED
    assert len(result.findings) == 1
    assert result.findings[0].stage == wmk.Stage.CRAWL
    assert result.findings[0].url == "https://target.com/page"
