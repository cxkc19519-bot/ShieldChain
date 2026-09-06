from __future__ import annotations

import importlib.util
import socketserver
from pathlib import Path


def _module(monkeypatch):
    monkeypatch.setattr(
        socketserver,
        "UnixStreamServer",
        getattr(socketserver, "UnixStreamServer", socketserver.TCPServer),
        raising=False,
    )
    path = Path(__file__).parents[3] / "endpoint_executor" / "server.py"
    spec = importlib.util.spec_from_file_location("shieldchain_endpoint_executor", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_isolation_policy_has_ttl_and_preserves_wazuh_ports(monkeypatch) -> None:
    module = _module(monkeypatch)
    calls: list[tuple[list[str], str | None, bool]] = []

    def fake_run(arguments, *, input_text=None, check=True):
        calls.append((arguments, input_text, check))
        if arguments[:2] == ["list", "tables"]:
            return "" if len(calls) == 1 else "table inet shieldchain_endpoint"
        if arguments[:2] == ["get", "element"]:
            return "elements = { 172.20.0.5 expires 59s }"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    monkeypatch.setattr(module, "_endpoint_ipv4", lambda: "172.20.0.5")

    result = module.isolate(60)

    policy = "\n".join(body or "" for _, body, _ in calls)
    assert "flags timeout" in policy
    assert "tcp dport { 1514, 1515 } accept" in policy
    assert result["isolation_status"] == "isolated"
    assert any("60s" in arguments for arguments, _, _ in calls)


def test_restore_deletes_only_the_endpoint_set_element(monkeypatch) -> None:
    module = _module(monkeypatch)
    calls: list[list[str]] = []

    def fake_run(arguments, *, input_text=None, check=True):
        del input_text, check
        calls.append(arguments)
        if arguments[:2] == ["list", "tables"]:
            return "table inet shieldchain_endpoint"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    monkeypatch.setattr(module, "_endpoint_ipv4", lambda: "172.20.0.5")

    result = module.restore()

    assert result["isolation_status"] == "connected"
    assert [
        "delete",
        "element",
        "inet",
        "shieldchain_endpoint",
        "isolated_ipv4",
        "{",
        "172.20.0.5",
        "}",
    ] in calls
