"""Deterministic, offline tokenization for security knowledge retrieval.

The tokenizer deliberately recognizes security identifiers before general words and uses a
small deterministic CJK segmenter.  It is not a language-model substitute, but it also is not
the misleading "split on whitespace" implementation that makes Chinese retrieval unusable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TOKEN_PATTERN = re.compile(
    r"(?P<cve>(?<![A-Za-z0-9_])CVE-\d{4}-\d{4,}(?![A-Za-z0-9_]))"
    r"|(?P<attack>ATT&CK|(?<![A-Za-z0-9_])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9_]))"
    r"|(?P<ipv4>(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_]))"
    r"|(?P<ipv6>(?<![A-Za-z0-9_])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]*)"
    r"|(?P<windows_path>(?<![A-Za-z0-9_])[A-Za-z]:\\[^\s<>\"'|]*[\w.-])"
    r"|(?P<unix_path>/(?:[^\s<>\"'|/]+/)*[^\s<>\"'|]+)"
    r"|(?P<command>(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_-]*\.(?:exe|ps1|bat|cmd|sh|py)"
    r"(?![A-Za-z0-9_]))"
    r"|(?P<word>[A-Za-z0-9_][A-Za-z0-9_.-]*)"
    r"|(?P<cjk>[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+)"
)

# This compact lexicon anchors common security vocabulary. Unknown CJK runs are paired in order,
# yielding useful deterministic terms even when a document has no spaces or punctuation.
_CJK_WORDS = frozenset(
    {
        "安全",
        "攻击",
        "恶意",
        "漏洞",
        "告警",
        "检测",
        "地址",
        "隔离",
        "感染",
        "主机",
        "日志",
        "证据",
        "响应",
        "流程",
        "权限",
        "身份",
        "威胁",
        "风险",
        "事件",
        "命令",
        "脚本",
        "勒索",
        "软件",
        "横向",
        "移动",
        "持久化",
        "提权",
        "防火墙",
        "数据库",
        "网络",
        "系统",
        "终端",
        "用户",
        "文件",
        "进程",
        "策略",
        "受感染",
    }
)
_MAX_CJK_WORD_LENGTH = max(map(len, _CJK_WORDS))


@dataclass(frozen=True, slots=True)
class TokenSpan:
    """A normalized token with an exact half-open offset into the supplied source text."""

    text: str
    start: int
    end: int

    def __post_init__(self) -> None:
        if not self.text:
            raise ValueError("token text must not be empty")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("token offsets must be a non-empty non-negative range")


class DeterministicSecurityTokenizer:
    """A stable tokenizer that keeps security entities atomic and emits CJK lexical terms."""

    def token_spans(self, text: str) -> tuple[TokenSpan, ...]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        spans: list[TokenSpan] = []
        for match in _TOKEN_PATTERN.finditer(text):
            value = match.group()
            if match.lastgroup == "cjk":
                spans.extend(self._cjk_spans(value, match.start()))
            else:
                # Sentence punctuation is not part of a POSIX path, despite being permitted by
                # most filesystems.  Dropping it also keeps the source offsets exact.
                if match.lastgroup == "unix_path":
                    value = value.rstrip(".,;:!?")
                spans.append(TokenSpan(value.casefold(), match.start(), match.start() + len(value)))
        return tuple(spans)

    def tokenize(self, text: str) -> tuple[str, ...]:
        return tuple(span.text for span in self.token_spans(text))

    def count(self, text: str) -> int:
        return len(self.token_spans(text))

    @staticmethod
    def _cjk_spans(value: str, offset: int) -> list[TokenSpan]:
        spans: list[TokenSpan] = []
        position = 0
        while position < len(value):
            matched: str | None = None
            upper = min(len(value), position + _MAX_CJK_WORD_LENGTH)
            for end in range(upper, position, -1):
                candidate = value[position:end]
                if candidate in _CJK_WORDS:
                    matched = candidate
                    break
            if matched is None:
                # Pair unknown Han characters rather than manufacturing one giant document token.
                matched = value[position : min(position + 2, len(value))]
            end = position + len(matched)
            spans.append(TokenSpan(matched, offset + position, offset + end))
            position = end
        return spans
