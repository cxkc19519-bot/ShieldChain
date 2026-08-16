from __future__ import annotations

import asyncio

import httpx

from shieldchain.qwen_experience.web_search import BingWebSearch, sanitize_search_query


def test_query_redacts_private_data_before_external_search() -> None:
    value = sanitize_search_query(
        "搜索 10.0.0.8 user@example.com api_key=secret-value C:\\Users\\a\\secret.txt CVE-2026-1234"
    )

    assert value is not None
    assert "10.0.0.8" not in value
    assert "user@example.com" not in value
    assert "secret-value" not in value
    assert "C:\\Users" not in value
    assert "CVE-2026-1234" in value


def test_bing_tool_parses_only_bounded_public_results() -> None:
    html = """
    <ol>
      <li class="b_algo"><h2><a href="https://example.com/advisory">安全公告</a></h2>
      <div class="b_caption"><p>官方漏洞说明。</p></div></li>
      <li class="b_algo"><h2><a href="javascript:alert(1)">无效链接</a></h2></li>
    </ol>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "最新安全公告"
        return httpx.Response(200, text=html, request=request)

    tool = BingWebSearch(transport=httpx.MockTransport(handler))
    results = asyncio.run(tool.search("最新安全公告", limit=5))

    assert len(results) == 1
    assert results[0].title == "安全公告"
    assert results[0].url == "https://example.com/advisory"
    assert results[0].snippet == "官方漏洞说明。"
