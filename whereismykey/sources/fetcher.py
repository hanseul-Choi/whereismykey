"""안전한 HTTP Fetcher + SSRF 가드 + HTML→텍스트 변환."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import urllib.parse

import httpx
from selectolax.parser import HTMLParser

logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2MB
MAX_REDIRECTS = 3
IGNORED_HTML_TAGS = "script, style, noscript, svg, head, iframe"


class FetcherError(Exception):
    """Fetcher 실행 또는 SSRF 가드 실패."""


def is_ip_safe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """주어진 IP 주소가 공인 IP인지 (사설/루프백/링크로컬 등이 아닌지) 검사."""
    # IPv4-mapped IPv6 주소 처리 (예: ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


async def is_safe_url(url: str) -> bool:
    """URL의 스킴과 대상 호스트 IP가 SSRF에 안전한지 검사."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname or hostname.lower() == "localhost":
        return False

    # 1. 호스트명 자체가 IP 리터럴인 경우
    try:
        ip = ipaddress.ip_address(hostname)
        return is_ip_safe(ip)
    except ValueError:
        pass

    # 2. 도메인명인 경우 비동기 DNS 해석
    try:
        loop = asyncio.get_running_loop()
        addr_infos = await loop.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except Exception as e:
        logger.debug("DNS lookup failed for %s: %s", hostname, e)
        return False

    if not addr_infos:
        return False

    for info in addr_infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if not is_ip_safe(ip):
                return False
        except ValueError:
            return False

    return True


def extract_text_from_html(html: str) -> str:
    """HTML 문서에서 스크립트/스타일을 제거하고 텍스트만 추출."""
    if not html:
        return ""
    try:
        parser = HTMLParser(html)
        for node in parser.css(IGNORED_HTML_TAGS):
            node.decompose()
        return parser.text(separator=" ", strip=True) or ""
    except Exception as e:
        logger.debug("Failed to parse HTML, fallback to raw text: %s", e)
        return html


class SafeFetcher:
    """SSRF 가드와 크기 제한이 적용된 안전한 HTTP Fetcher."""

    def __init__(
        self,
        *,
        user_agent: str = "whereismykey/0.1 (+security-scan)",
        timeout_s: float = 10.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self._custom_client = client

    async def fetch_text(self, url: str) -> str:
        """URL의 텍스트 콘텐츠를 안전하게 가져온다. (SSRF 검증, 리다이렉트 제어, 크기 제한)."""
        current_url = url
        redirect_count = 0

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,text/plain,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

        # _custom_client가 제공되지 않은 경우 새로운 클라이언트 사용
        client = self._custom_client or httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout_s,
            follow_redirects=False,
        )

        should_close = self._custom_client is None

        try:
            while True:
                if not await is_safe_url(current_url):
                    raise FetcherError(f"URL is blocked by SSRF guard: {current_url}")

                try:
                    resp = await client.get(current_url)
                except httpx.RequestError as e:
                    raise FetcherError(f"Network error while fetching {current_url}: {e}") from e

                # 리다이렉트 응답인 경우
                if resp.is_redirect:
                    redirect_count += 1
                    if redirect_count > MAX_REDIRECTS:
                        raise FetcherError(f"Too many redirects (max {MAX_REDIRECTS})")
                    location = resp.headers.get("Location")
                    if not location:
                        raise FetcherError("Redirect response without Location header")
                    current_url = urllib.parse.urljoin(current_url, location)
                    continue

                if resp.status_code != 200:
                    raise FetcherError(f"Non-200 status code: {resp.status_code} for {current_url}")

                content_type = resp.headers.get("Content-Type", "").lower()
                # 바이너리 타입 사전 차단 (이미지, 동영상, zip 등)
                if any(
                    binary_type in content_type
                    for binary_type in [
                        "image/",
                        "video/",
                        "audio/",
                        "application/zip",
                        "application/octet-stream",
                        "application/pdf",
                    ]
                ):
                    return ""

                # 크기 확인
                content_bytes = resp.content
                if len(content_bytes) > self.max_bytes:
                    raise FetcherError(
                        f"Response body too large ({len(content_bytes)} > {self.max_bytes} bytes)"
                    )

                text = resp.text
                if "html" in content_type:
                    return extract_text_from_html(text)
                return text
        finally:
            if should_close:
                await client.aclose()
