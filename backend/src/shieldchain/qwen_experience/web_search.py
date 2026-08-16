"""Bounded Bing web-search tool for the local Qwen experience."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


class BingSearchUnavailable(Exception):
    """Bing could not return a usable public result page."""


@dataclass(frozen=True, slots=True)
class BingSearchResult:
    title: str
    url: str
    snippet: str


def sanitize_search_query(value: str) -> str | None:
    """Remove common secrets and private identifiers before external search."""
    cleaned = " ".join(value.split())[:500]
    cleaned = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[邮箱已隐藏]", cleaned)
    cleaned = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b", "[标识符已隐藏]", cleaned)
    cleaned = re.sub(
        r"(?i)\b(?:bearer|api[_ -]?key|token|secret|password)\s*[:=]\s*\S+",
        "[凭据已隐藏]",
        cleaned,
    )
    cleaned = re.sub(r"(?i)(?:[A-Z]:\\|/home/|/users/|/root/)\S+", "[本地路径已隐藏]", cleaned)

    def redact_private_ip(match: re.Match[str]) -> str:
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return "[内网IP已隐藏]" if address.is_private else match.group(0)

    cleaned = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", redact_private_ip, cleaned)
    cleaned = " ".join(cleaned.split())[:180].strip()
    return cleaned if len(cleaned) >= 2 else None


class BingWebSearch:
    """Search only Bing's public result page; never follows result links."""

    _endpoint = "https://cn.bing.com/search"

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    async def search(self, query: str, *, limit: int = 5) -> tuple[BingSearchResult, ...]:
        normalized = sanitize_search_query(query)
        if normalized is None:
            return ()
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, transport=self._transport
            ) as client:
                response = await client.get(
                    self._endpoint,
                    params={"q": normalized, "count": min(max(limit, 1), 8)},
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 Chrome/127 Safari/537.36"
                        ),
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
                    },
                    timeout=12,
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise BingSearchUnavailable("Bing 搜索暂时不可用") from error

        results: list[BingSearchResult] = []
        document = BeautifulSoup(response.text, "html.parser")
        for row in document.select("li.b_algo"):
            anchor = row.select_one("h2 a[href]")
            if anchor is None:
                continue
            title = " ".join(anchor.get_text(" ", strip=True).split())[:180]
            url = str(anchor.get("href", "")).strip()
            parsed = urlparse(url)
            if not title or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            paragraph = row.select_one(".b_caption p") or row.select_one("p")
            snippet = (
                " ".join(paragraph.get_text(" ", strip=True).split())[:500]
                if paragraph is not None
                else ""
            )
            results.append(BingSearchResult(title=title, url=url, snippet=snippet))
            if len(results) >= limit:
                break
        if not results:
            raise BingSearchUnavailable("Bing 未返回可解析的搜索结果")
        return tuple(results)
