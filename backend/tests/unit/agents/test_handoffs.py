from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.agents.handoffs import (
    HandoffClaimStatus,
    HandoffDraft,
    HandoffServiceError,
    StructuredHandoffService,
)

NOW = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
CASE = UUID("10000000-0000-0000-0000-000000000001")


def reference(*, case_id: UUID = CASE, digest: str = "a" * 64):
    return EvidenceReference(uuid4(), case_id, "edr:1", NOW, digest)


def draft(*, refs=None, sender=AgentRole.ALERT_TRIAGE):
    return HandoffDraft(
        uuid4(),
        CASE,
        sender,
        AgentRole.THREAT_INVESTIGATION,
        "Endpoint behavior requires investigation",
        refs if refs is not None else (reference(),),
        0.7,
        ("Was the account used elsewhere?",),
        ("Query endpoint timeline",),
        NOW,
    )


class Resolver:
    def __init__(self, replacement=None, *, fail=False):
        self.replacement = replacement
        self.fail = fail
        self.calls = []

    def resolve(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise HandoffServiceError("reference unavailable")
        return self.replacement or kwargs["references"]


class Writer:
    def __init__(self):
        self.calls = []

    def append_handoff(self, handoff, **kwargs):
        self.calls.append((handoff, kwargs))


def test_service_reresolves_then_appends_and_returns_unverified_claim() -> None:
    resolver = Resolver()
    writer = Writer()
    subject = StructuredHandoffService(resolver=resolver, writer=writer)
    item = draft()

    claim = subject.submit(item, acting_role=item.sender, request_id="request-1")

    assert len(resolver.calls) == 1
    assert len(writer.calls) == 1
    assert writer.calls[0][0] is claim.packet
    assert claim.status is HandoffClaimStatus.UNVERIFIED
    assert claim.confirmed_fact is False
    assert claim.packet.recommended_actions == item.proposed_actions


def test_only_declared_sender_can_submit_and_denial_has_no_side_effects() -> None:
    resolver = Resolver()
    writer = Writer()
    subject = StructuredHandoffService(resolver=resolver, writer=writer)

    with pytest.raises(HandoffServiceError, match="declared sender"):
        subject.submit(draft(), acting_role=AgentRole.REPORTING, request_id="request-1")
    assert resolver.calls == []
    assert writer.calls == []


def test_forged_or_changed_resolution_is_rejected_before_append() -> None:
    item = draft()
    forged = reference(digest="b" * 64)
    writer = Writer()
    subject = StructuredHandoffService(resolver=Resolver((forged,)), writer=writer)

    with pytest.raises(HandoffServiceError, match="do not match"):
        subject.submit(item, acting_role=item.sender, request_id="request-1")
    assert writer.calls == []


def test_resolution_failure_is_explicit_and_not_persisted() -> None:
    resolver = Resolver(fail=True)
    writer = Writer()

    with pytest.raises(HandoffServiceError, match="unavailable"):
        StructuredHandoffService(resolver=resolver, writer=writer).submit(
            draft(), acting_role=AgentRole.ALERT_TRIAGE, request_id="request-1"
        )
    assert writer.calls == []


def test_handoff_requires_same_case_trusted_reference_and_proposed_action() -> None:
    with pytest.raises(HandoffServiceError, match="another case"):
        draft(refs=(reference(case_id=uuid4()),))
    with pytest.raises(HandoffServiceError, match="trusted references"):
        draft(refs=())
    with pytest.raises(ValueError, match="proposed_actions"):
        HandoffDraft(
            uuid4(),
            CASE,
            AgentRole.ALERT_TRIAGE,
            AgentRole.THREAT_INVESTIGATION,
            "conclusion",
            (reference(),),
            0.5,
            (),
            (),
            NOW,
        )
