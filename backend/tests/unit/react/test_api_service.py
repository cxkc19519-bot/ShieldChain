from datetime import UTC, datetime
from uuid import UUID

from shieldchain.react.api_service import _action, _reference

NOW = datetime(2026, 7, 23, 22, tzinfo=UTC)


def reference() -> dict[str, object]:
    return {
        "id": str(UUID(int=1)),
        "kind": "evidence",
        "case_id": str(UUID(int=2)),
        "source_id": "siem:alert-1",
        "observed_at": NOW.isoformat(),
        "integrity_sha256": "a" * 64,
        "raw_prompt": "private prompt",
        "adapter_result": "private raw result",
    }


def test_reference_projection_ignores_non_allowlisted_storage_fields() -> None:
    payload = _reference(reference()).model_dump_json()
    assert "siem:alert-1" in payload
    assert "private prompt" not in payload
    assert "private raw result" not in payload
    assert "case_id" not in payload


def test_action_projection_only_exposes_registered_expected_state_fields() -> None:
    payload = _action(
        {
            "id": str(UUID(int=3)),
            "action": "proposed:block_ip",
            "target": "203.0.113.8",
            "expected_state": {
                "firewall_status": "blocked",
                "chain_of_thought": "private reasoning",
            },
            "references": [reference()],
            "raw_result": "private adapter result",
        }
    ).model_dump_json()
    assert "firewall_status" in payload
    assert "chain_of_thought" not in payload
    assert "private reasoning" not in payload
    assert "private adapter result" not in payload
