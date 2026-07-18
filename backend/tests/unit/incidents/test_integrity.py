from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest

from shieldchain.incidents.integrity import create_evidence, verify_evidence_integrity

NOW = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)


def _valid():
    return create_evidence(
        evidence_type="network_connection",
        source="simulated_edr",
        observed_at=NOW,
        summary="Active connection",
        raw_reference="simulation://connection/1",
        confidence=0.98,
        confirmed=True,
        payload={"remote_ip": "198.51.100.24", "nested": [1, {"ok": True}]},
    )


def test_canonical_evidence_is_deterministic_and_verified() -> None:
    first = _valid()
    second = _valid()
    assert first.id == second.id
    assert first.integrity_sha256 == second.integrity_sha256
    assert verify_evidence_integrity(first) is True


@pytest.mark.parametrize(
    "tamper",
    [
        lambda item: replace(item, summary="changed"),
        lambda item: replace(item, raw_reference="simulation://changed"),
        lambda item: replace(item, confidence=0.5),
        lambda item: replace(item, confirmed=False),
        lambda item: replace(item, payload={"remote_ip": "203.0.113.9"}),
        lambda item: replace(item, integrity_sha256="0" * 64),
        lambda item: replace(item, id=UUID(int=1)),
    ],
)
def test_every_proof_field_and_digest_or_id_tamper_invalidates_verification(tamper) -> None:
    assert verify_evidence_integrity(tamper(_valid())) is False
