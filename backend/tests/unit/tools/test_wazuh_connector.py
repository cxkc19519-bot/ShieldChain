from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import ExecutionOutcome, TrustedToolRequest, VerificationOutcome
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.wazuh_connector import WazuhAdapterProvider, WazuhHttpAdapter

NOW = datetime(2026, 9, 6, 8, tzinfo=UTC)
CASE, RUN, PLAN, REQUEST_ID, EVIDENCE = (UUID(int=value) for value in range(9201, 9206))


def bound_request(tool="query_endpoint_state"):
    evidence = EvidenceReference(EVIDENCE, CASE, "wazuh:002", NOW, "b" * 64)
    request = TrustedToolRequest(
        id=REQUEST_ID,
        case_id=CASE,
        run_id=RUN,
        plan_id=PLAN,
        idempotency_key="real-wazuh:query:9204",
        caller_role=AgentRole.RESPONSE_PLANNING,
        tool_name=tool,
        tool_version="1",
        arguments=(
            {
                "endpoint_id": "002",
                "reason_code": "containment_required",
                "isolation_ttl_seconds": 60,
            }
            if tool == "isolate_endpoint"
            else (
                {"endpoint_id": "002", "reason_code": "approved_rollback"}
                if tool == "restore_endpoint"
                else {"endpoint_id": "002"}
            )
        ),
        expected_state={
            "isolation_status": "isolated" if tool == "isolate_endpoint" else "connected"
        },
        rollback_strategy="Read-only query requires no rollback.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return default_tool_registry().bind(request)


def test_wazuh_adapter_queries_and_independently_verifies(monkeypatch) -> None:
    calls = []

    def fake_post(self, path, payload):
        del self
        calls.append((path, payload))
        return {
            "ok": True,
            "isolation_status": "connected",
            "summary": "queried",
        }

    monkeypatch.setattr(WazuhHttpAdapter, "_post", fake_post)
    adapter = WazuhHttpAdapter(
        base_url="http+unix:///run/shieldchain-wazuh-executor/executor.sock",
        token="a-secure-test-token-with-24-characters",
    )
    execution = adapter.execute(bound_request())
    verification = adapter.verify(bound_request(), execution, now=NOW)

    assert execution.outcome is ExecutionOutcome.SUCCEEDED
    assert verification.outcome is VerificationOutcome.VERIFIED
    assert calls == [
        ("/v1/wazuh/agent/query", {"agent_id": "002"}),
        ("/v1/wazuh/agent/query", {"agent_id": "002"}),
    ]


@pytest.mark.parametrize(
    ("tool", "path", "payload", "status"),
    [
        (
            "isolate_endpoint",
            "/v1/wazuh/agent/isolate",
            {"agent_id": "002", "ttl_seconds": 60},
            "isolated",
        ),
        (
            "restore_endpoint",
            "/v1/wazuh/agent/restore",
            {"agent_id": "002"},
            "connected",
        ),
    ],
)
def test_wazuh_adapter_routes_fixed_endpoint_mutations(
    monkeypatch, tool, path, payload, status
) -> None:
    calls = []

    def fake_post(self, request_path, request_payload):
        del self
        calls.append((request_path, request_payload))
        return {"ok": True, "isolation_status": status, "summary": "changed"}

    monkeypatch.setattr(WazuhHttpAdapter, "_post", fake_post)
    adapter = WazuhHttpAdapter(
        base_url="http+unix:///run/shieldchain-wazuh-executor/executor.sock",
        token="a-secure-test-token-with-24-characters",
    )
    request = bound_request(tool)
    execution = adapter.execute(request)
    verification = adapter.verify(request, execution, now=NOW)
    assert execution.outcome is ExecutionOutcome.SUCCEEDED
    assert verification.outcome is VerificationOutcome.VERIFIED
    assert calls == [
        (path, payload),
        ("/v1/wazuh/agent/query", {"agent_id": "002"}),
    ]


def test_wazuh_adapter_rejects_non_unix_transport_and_short_token() -> None:
    with pytest.raises(ValueError, match="Unix socket"):
        WazuhHttpAdapter(
            base_url="http://127.0.0.1:9181",
            token="a-secure-test-token-with-24-characters",
        )
    with pytest.raises(ValueError, match="24 characters"):
        WazuhHttpAdapter(
            base_url="http+unix:///run/shieldchain-wazuh-executor/executor.sock",
            token="short",
        )


def test_provider_routes_only_wazuh_bound_runs() -> None:
    fallback = MagicMock()
    fallback_adapter = MagicMock()
    fallback.for_run.return_value = fallback_adapter
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = str(RUN)
    provider = WazuhAdapterProvider(
        fallback,
        base_url="http+unix:///run/shieldchain-wazuh-executor/executor.sock",
        token="a-secure-test-token-with-24-characters",
    )

    routed = provider.for_run(session, tenant_id=UUID(int=1), run_id=RUN, now=NOW)
    assert routed is not fallback_adapter

    session.execute.return_value.scalar_one_or_none.return_value = None
    assert provider.for_run(
        session, tenant_id=UUID(int=1), run_id=UUID(int=999), now=NOW
    ) is fallback_adapter
