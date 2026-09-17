"""whereismykey Python SDK 단위 테스트."""

from __future__ import annotations

import httpx
import pytest
import respx
import whereismykey as wmk

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
