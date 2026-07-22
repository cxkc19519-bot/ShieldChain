from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import ConfirmedFact, EvidenceReference, Hypothesis
from shieldchain.agents.memory import (
    CaseMemoryCompressor,
    CaseMemoryInput,
    ExperienceCandidate,
    ExperiencePromotionService,
    HumanConfirmation,
    LayeredMemoryEntry,
    MemoryBoundaryError,
    MemoryContentKind,
    MemoryLayer,
    ProtectedArtifactKind,
    ProtectedArtifactReference,
)

NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
CASE = UUID("10000000-0000-0000-0000-000000000001")


def reference():
    return EvidenceReference(uuid4(), CASE, "edr:1", NOW, "a" * 64)


def fact():
    return ConfirmedFact(uuid4(), "PowerShell contacted malicious IP", True, (reference(),), 1, NOW)


def hypothesis(statement: str):
    return Hypothesis(uuid4(), statement, 0.5, (reference(),))


def artifact(kind: ProtectedArtifactKind):
    return ProtectedArtifactReference(uuid4(), CASE, kind, f"{kind.value}:1", "b" * 64, NOW)


@pytest.mark.parametrize(
    ("layer", "kind", "case_id", "references", "expires_at"),
    (
        (MemoryLayer.WORKING, MemoryContentKind.WORK_ITEM, CASE, (), NOW + timedelta(hours=1)),
        (MemoryLayer.CASE, MemoryContentKind.CASE_NOTE, CASE, (reference(),), None),
        (MemoryLayer.SESSION, MemoryContentKind.USER_PREFERENCE, None, (), None),
        (MemoryLayer.AUDIT, MemoryContentKind.AUDIT_SUMMARY, CASE, (), None),
    ),
)
def test_each_memory_layer_accepts_only_its_bounded_shape(
    layer, kind, case_id, references, expires_at
) -> None:
    entry = LayeredMemoryEntry(
        uuid4(), layer, kind, "bounded content", NOW, case_id, references, expires_at
    )
    assert entry.layer is layer


def test_session_memory_cannot_hold_security_evidence() -> None:
    with pytest.raises(MemoryBoundaryError, match="security references"):
        LayeredMemoryEntry(
            uuid4(),
            MemoryLayer.SESSION,
            MemoryContentKind.CONVERSATION_SUMMARY,
            "summary",
            NOW,
            None,
            (reference(),),
        )


@pytest.mark.parametrize("content", ("raw_prompt=secret", "chain of thought: hidden", "思维链"))
def test_audit_memory_rejects_prompts_and_chain_of_thought(content: str) -> None:
    with pytest.raises(MemoryBoundaryError, match="prompts or chain"):
        LayeredMemoryEntry(
            uuid4(), MemoryLayer.AUDIT, MemoryContentKind.AUDIT_SUMMARY, content, NOW, CASE
        )


def test_compression_preserves_facts_references_and_protected_artifacts() -> None:
    confirmed = fact()
    active = hypothesis("Endpoint may be compromised")
    expired = hypothesis("Old unsupported idea")
    artifacts = tuple(artifact(kind) for kind in ProtectedArtifactKind)
    memory = CaseMemoryInput(
        CASE,
        (confirmed,),
        (active, expired),
        {active.id: NOW + timedelta(hours=1), expired.id: NOW - timedelta(seconds=1)},
        artifacts,
        ("A" * 200,),
    )

    result = CaseMemoryCompressor().compress(memory, now=NOW, max_summary_characters=64)

    assert result.truncated is True
    assert result.confirmed_facts == (confirmed,)
    assert set(result.summary_references) == set(confirmed.references + active.references)
    assert result.protected_artifacts == artifacts
    assert result.active_hypotheses == (active,)
    assert result.archived_hypotheses == (expired,)
    assert "Old unsupported idea" not in result.summary


class FakeExperiencePort:
    def __init__(self) -> None:
        self.records = []

    def publish(self, record) -> None:
        self.records.append(record)


def confirmation(*, approved: bool = True, case_id: UUID = CASE):
    return HumanConfirmation(uuid4(), case_id, uuid4(), approved, NOW)


def test_experience_requires_human_confirmation_and_prior_redaction() -> None:
    port = FakeExperiencePort()
    service = ExperiencePromotionService(port)
    safe = ExperienceCandidate(CASE, "Review encoded PowerShell alerts", (reference(),), True)
    record = service.promote(safe, confirmation())
    assert port.records == [record]
    assert record.references == safe.references

    with pytest.raises(MemoryBoundaryError, match="human approval"):
        service.promote(safe, confirmation(approved=False))
    with pytest.raises(MemoryBoundaryError, match="redacted"):
        service.promote(
            ExperienceCandidate(CASE, "Review encoded PowerShell alerts", (reference(),), False),
            confirmation(),
        )
    with pytest.raises(MemoryBoundaryError, match="sensitive"):
        service.promote(
            ExperienceCandidate(CASE, "api_key=sk-live-123456789", (reference(),), True),
            confirmation(),
        )
    assert len(port.records) == 1
