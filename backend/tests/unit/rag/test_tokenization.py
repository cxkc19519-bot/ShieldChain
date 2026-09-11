from __future__ import annotations

from shieldchain.rag.tokenization import DeterministicSecurityTokenizer


def test_security_tokenizer_preserves_security_entities_and_paths() -> None:
    tokens = DeterministicSecurityTokenizer().tokenize(
        "Investigate CVE-2024-3094 from 10.0.0.8 via ATT&CK T1059.003; "
        "run powershell.exe -NoProfile on C:\\Temp\\script.ps1 and /var/log/auth.log."
    )

    assert "cve-2024-3094" in tokens
    assert "10.0.0.8" in tokens
    assert "att&ck" in tokens
    assert "t1059.003" in tokens
    assert "powershell.exe" in tokens
    assert "c:\\temp\\script.ps1" in tokens
    assert "/var/log/auth.log" in tokens


def test_security_tokenizer_segments_chinese_without_spaces() -> None:
    tokens = DeterministicSecurityTokenizer().tokenize("检测恶意IP地址并隔离受感染主机")

    assert "恶意" in tokens
    assert "地址" in tokens
    assert "感染" in tokens
    assert len(tokens) > 3


def test_security_tokenizer_is_deterministic_and_exposes_spans() -> None:
    tokenizer = DeterministicSecurityTokenizer()
    first = tokenizer.token_spans("告警 CVE-2024-3094")

    assert first == tokenizer.token_spans("告警 CVE-2024-3094")
    assert [span.text for span in first][-1] == "cve-2024-3094"
    assert all("告警 CVE-2024-3094"[span.start : span.end] for span in first)


def test_security_entities_remain_atomic_when_adjacent_to_chinese() -> None:
    tokens = DeterministicSecurityTokenizer().tokenize(
        "发现CVE-2024-3094关联ATT&CKT1059.003来自10.0.0.8执行powershell.exe路径C:\\Temp\\a.ps1"
    )

    assert {"cve-2024-3094", "att&ck", "t1059.003", "10.0.0.8", "powershell.exe"} <= set(tokens)
    assert "c:\\temp\\a.ps1" in tokens
