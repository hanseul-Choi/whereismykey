"""WebCrawlSource (웹 크롤러 소스) 단위 테스트."""

from __future__ import annotations

import httpx
import pytest
import respx
from whereismykey.core.key_spec import KeySpec
from whereismykey.core.models import Confidence, Stage
from whereismykey.sources.base import ScanOptions
from whereismykey.sources.crawl import DDG_SEARCH_URL, WebCrawlSource

from tests.conftest import FAKE_KEY, FAKE_POSTFIX, FAKE_PREFIX, FAKE_SHA256

DDG_SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<body>
  <div class="result results_links results_links_deep web-result">
    <div class="links_main links_deep result__body">
      <h2 class="result__title">
        <a class="result__a" href="https://exposed-site.com/config.html">Exposed Secret Page</a>
      </h2>
      <a class="result__url" href="https://exposed-site.com/config.html">exposed-site.com/config.html</a>
      <div class="result__snippet">Here is a snippet showing config...</div>
    </div>
  </div>
  <div class="result results_links results_links_deep web-result">
    <div class="links_main links_deep result__body">
      <h2 class="result__title">
        <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fa.io%2Fk">Link</a>
      </h2>
      <a class="result__url" href="https://a.io/k">a.io/k</a>


    </div>
  </div>
</body>
</html>
"""


@pytest.fixture
def test_spec() -> KeySpec:
    return KeySpec(
        prefix=FAKE_PREFIX,
        postfix=FAKE_POSTFIX,
        sha256=FAKE_SHA256,
        name="test-crawl-key",
    )


@pytest.fixture(autouse=True)
def mock_dns_safe_url(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _safe(url: str) -> bool:
        return True

    monkeypatch.setattr("whereismykey.sources.fetcher.is_safe_url", _safe)


def test_crawl_source_metadata() -> None:
    source = WebCrawlSource()
    assert source.name == "web_crawler"
    assert source.stage == Stage.CRAWL


@pytest.mark.asyncio
@respx.mock
async def test_search_engine_crawl_and_match(test_spec: KeySpec) -> None:
    # 1. Mock DuckDuckGo HTML Search POST
    respx.post(DDG_SEARCH_URL).mock(return_value=httpx.Response(200, text=DDG_SAMPLE_HTML))

    # 2. Mock target pages
    respx.get("https://exposed-site.com/config.html").mock(
        return_value=httpx.Response(200, text=f"<html><body>API_KEY = '{FAKE_KEY}'</body></html>")
    )
    respx.get("https://a.io/k").mock(
        return_value=httpx.Response(200, text="clean page with no secrets")
    )

    source = WebCrawlSource()
    options = ScanOptions(max_results_per_source=10)

    findings = await source.search_and_match(test_spec, options)

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].stage == Stage.CRAWL
    assert findings[0].source == "web_crawler"
    assert findings[0].url == "https://exposed-site.com/config.html"
    assert FAKE_PREFIX in findings[0].snippet


@pytest.mark.asyncio
@respx.mock
async def test_crawl_custom_seed_urls_with_depth(test_spec: KeySpec) -> None:
    # 1. DuckDuckGo returns empty search results
    respx.post(DDG_SEARCH_URL).mock(
        return_value=httpx.Response(200, text="<html><body>No results</body></html>")
    )

    # 2. Custom seed URL contains a link to internal child page
    seed_url = "https://custom-site.test/docs"
    child_url = "https://custom-site.test/docs/secret-page"

    respx.get(seed_url).mock(
        return_value=httpx.Response(
            200,
            text='<html><body><a href="/docs/secret-page">Secret link</a></body></html>',
        )
    )

    respx.get(child_url).mock(
        return_value=httpx.Response(
            200,
            text=f"<html><body>Secret revealed: {FAKE_KEY}</body></html>",
        )
    )

    source = WebCrawlSource()
    options = ScanOptions(
        crawl_urls=[seed_url],
        crawl_max_depth=1,
    )

    findings = await source.search_and_match(test_spec, options)

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].url == child_url


@pytest.mark.asyncio
@respx.mock
async def test_crawl_search_engine_failure_gracefully_handled(test_spec: KeySpec) -> None:
    # DuckDuckGo returns 500 error
    respx.post(DDG_SEARCH_URL).mock(return_value=httpx.Response(500, text="Internal Server Error"))

    source = WebCrawlSource()
    options = ScanOptions()

    findings = await source.search_and_match(test_spec, options)
    assert findings == []
