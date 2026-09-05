from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import ExecutionOutcome, TrustedToolRequest, VerificationOutcome
from shieldchain.tools.firewall_connector import NftablesAdapterProvider, NftablesHttpAdapter
from shieldchain.tools.registry import default_tool_registry

NOW = datetime(2026, 9, 5, 8, tzinfo=UTC)
CASE, RUN, PLAN, REQUEST_ID, EVIDENCE = (UUID(int=value) for value in range(9101, 9106))


class Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self._payload[:size]


def bound_block():
    evidence = EvidenceReference(EVIDENCE, CASE, "suricata:9105", NOW, "a" * 64)
    request = TrustedToolRequest(
        id=REQUEST_ID,
        case_id=CASE,
        run_id=RUN,
        plan_id=PLAN,
        idempotency_key="real-firewall:block:9104",
        caller_role=AgentRole.RESPONSE_PLANNING,
        tool_name="block_ip",
        tool_version="1",
        arguments={"target_ip": "203.0.113.25", "rule_ttl_seconds": 300},
        expected_state={"firewall_status": "blocked"},
        rollback_strategy="Wait for the bounded nftables timeout or remove the exact set element.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return default_tool_registry().bind(request)


def test_real_firewall_adapter_executes_and_independently_verifies(monkeypatch) -> None:
    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        path = request.full_url.rsplit("/", 1)[-1]
        if path == "block":
            return Response({"ok": True, "firewall_status": "blocked", "summary": "blocked"})
        return Response({"ok": True, "firewall_status": "blocked", "summary": "queried"})

    monkeypatch.setattr("shieldchain.tools.firewall_connector.urlopen", fake_urlopen)
    adapter = NftablesHttpAdapter(
        base_url="http://executor.test:9180",
        token="a-secure-test-token-with-24-characters",
    )
    execution = adapter.execute(bound_block())
    verification = adapter.verify(bound_block(), execution, now=NOW)

    assert execution.outcome is ExecutionOutcome.SUCCEEDED
    assert verification.outcome is VerificationOutcome.VERIFIED
    assert [item[0].full_url for item in requests] == [
        "http://executor.test:9180/v1/firewall/block",
        "http://executor.test:9180/v1/firewall/query",
    ]
    assert all(item[0].get_header("Authorization").startswith("Bearer ") for item in requests)


def test_real_firewall_adapter_requires_a_nontrivial_token() -> None:
    with pytest.raises(ValueError, match="24 characters"):
        NftablesHttpAdapter(base_url="http://executor.test:9180", token="short")


def test_real_firewall_adapter_accepts_an_absolute_unix_socket_url() -> None:
    adapter = NftablesHttpAdapter(
        base_url="http+unix:///run/shieldchain-executor/executor.sock",
        token="a-secure-test-token-with-24-characters",
    )
    assert adapter._unix_socket == "/run/shieldchain-executor/executor.sock"


def test_provider_routes_explicit_wazuh_run_to_firewall_without_simulation() -> None:
    fallback = MagicMock()
    fallback.for_run.return_value = None
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = str(RUN)
    provider = NftablesAdapterProvider(
        fallback,
        base_url="http://executor.test:9180",
        token="a-secure-test-token-with-24-characters",
    )

    adapter = provider.for_run(
        session, tenant_id=UUID(int=1), run_id=RUN, now=NOW
    )

    assert isinstance(adapter, NftablesHttpAdapter)
    session.execute.assert_called_once()


def test_provider_rejects_unbound_non_simulation_run() -> None:
    fallback = MagicMock()
    fallback.for_run.return_value = None
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    provider = NftablesAdapterProvider(
        fallback,
        base_url="http://executor.test:9180",
        token="a-secure-test-token-with-24-characters",
    )

    assert provider.for_run(
        session, tenant_id=UUID(int=1), run_id=RUN, now=NOW
    ) is None
