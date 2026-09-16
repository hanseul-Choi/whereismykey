"""SafeFetcher 및 SSRF 가드 단위 테스트."""

from __future__ import annotations

import ipaddress

import httpx
import pytest
import respx
from app.sources.fetcher import (
    FetcherError,
    SafeFetcher,
    extract_text_from_html,
    is_ip_safe,
    is_safe_url,
)


def test_is_ip_safe() -> None:
    # 사설 / 루프백 / 링크로컬 / 특수 대역 차단
    assert not is_ip_safe(ipaddress.ip_address("127.0.0.1"))
    assert not is_ip_safe(ipaddress.ip_address("10.0.0.1"))
    assert not is_ip_safe(ipaddress.ip_address("172.16.0.1"))
    assert not is_ip_safe(ipaddress.ip_address("192.168.1.100"))
    assert not is_ip_safe(ipaddress.ip_address("169.254.169.254"))  # AWS 메타데이터 IP
    assert not is_ip_safe(ipaddress.ip_address("0.0.0.0"))
    assert not is_ip_safe(ipaddress.ip_address("::1"))
    assert not is_ip_safe(ipaddress.ip_address("fe80::1"))

    # 공인 IP 통과
    assert is_ip_safe(ipaddress.ip_address("8.8.8.8"))
    assert is_ip_safe(ipaddress.ip_address("1.1.1.1"))
    assert is_ip_safe(ipaddress.ip_address("93.184.216.34"))


@pytest.mark.asyncio
async def test_is_safe_url_blocks_unsafe() -> None:
    assert not await is_safe_url("http://localhost")
    assert not await is_safe_url("http://127.0.0.1:8000")
    assert not await is_safe_url("http://10.1.2.3/secret")
    assert not await is_safe_url("http://169.254.169.254/latest/meta-data/")
    assert not await is_safe_url("ftp://example.com/file")
    assert not await is_safe_url("file:///etc/passwd")
    assert not await is_safe_url("gopher://127.0.0.1:70")


def test_extract_text_from_html() -> None:
    html = """
    <html>
        <head><title>Test Page</title><script>alert('xss');</script></head>
        <style>body { color: red; }</style>
        <body>
            <h1>Title Header</h1>
            <p>Here is some content with <a href="#">a link</a>.</p>
            <noscript>JavaScript is required</noscript>
        </body>
    </html>
    """
    text = extract_text_from_html(html)
    assert "Title Header" in text
    assert "Here is some content with a link" in text
    assert "alert('xss')" not in text
    assert "body { color: red; }" not in text
    assert "JavaScript is required" not in text


@pytest.mark.asyncio
@respx.mock
async def test_fetcher_fetches_safe_url() -> None:
    url = "https://example.com/blog/post"
    html_body = "<html><body><h1>Hello World</h1><p>My Secret Key Test</p></body></html>"

    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text=html_body,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
    )

    async with httpx.AsyncClient() as client:
        fetcher = SafeFetcher(client=client)
        # Mock is_safe_url to avoid actual DNS query during test
        text = await fetcher.fetch_text(url)
        assert "Hello World" in text
        assert "My Secret Key Test" in text


@pytest.mark.asyncio
async def test_fetcher_blocks_private_ip() -> None:
    fetcher = SafeFetcher()
    with pytest.raises(FetcherError, match="SSRF guard"):
        await fetcher.fetch_text("http://127.0.0.1/admin")


@pytest.mark.asyncio
@respx.mock
async def test_fetcher_exceeds_max_bytes() -> None:
    url = "https://example.com/huge"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            content=b"A" * 1000,
            headers={"Content-Type": "text/plain"},
        )
    )

    async with httpx.AsyncClient() as client:
        fetcher = SafeFetcher(max_bytes=500, client=client)
        with pytest.raises(FetcherError, match="too large"):
            await fetcher.fetch_text(url)
