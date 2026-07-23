from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.control import (
    ToolAlreadyDispatched,
    ToolControlError,
    TrustedToolControlService,
)
from shieldchain.tools.domain import TrustedToolCall, TrustedToolCallStatus, TrustedToolRequest

NOW = datetime(2026, 7, 23, 13, tzinfo=UTC)
TENANT, ACTOR, CASE, RUN, PLAN, CALL, EVIDENCE = (UUID(int=value) for value in range(1701, 1708))


def call(status=TrustedToolCallStatus.APPROVED, *, call_id=CALL):
    request = TrustedToolRequest(
        call_id,
        CASE,
        RUN,
        PLAN,
        "phase5:control:1701",
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Reverse rule.",
        (EvidenceReference(EVIDENCE, CASE, "siem:control", NOW, "c" * 64),),
        NOW,
    )
    return TrustedToolCall(request, status, 2, None, NOW)


class Store:
    def __init__(self, calls=()):
        self.calls = list(calls)
        self.events = []
        self.control = None

    def transition_controlled_call(self, *, tenant_id, current, target, now, request_id):
        changed = current.transition(target, now=now)
        self.calls = [
            changed if item.request.id == current.request.id else item for item in self.calls
        ]
        return changed

    def append_control_event(self, event):
        self.events.append(event)

    def latest_call_event(self, *, tenant_id, request_id):
        return next((item for item in reversed(self.events) if item.request_id == request_id), None)

    def get_control(self, *, tenant_id):
        return self.control

    def set_control(self, *, current, changed):
        if current is not self.control:
            raise RuntimeError("stale control")
        self.control = changed
        return changed

    def pending_calls(self, *, tenant_id):
        return tuple(
            item for item in self.calls if item.status in TrustedToolControlService._CONTROLLABLE
        )


def test_pause_resume_and_cancel_preserve_trusted_prior_state() -> None:
    store, service = Store(), TrustedToolControlService()
    paused = service.pause(
        tenant_id=TENANT,
        call=call(),
        actor_subject_id=ACTOR,
        reason="Operator review",
        now=NOW,
        request_id="pause",
        store=store,
    )
    resumed = service.resume(
        tenant_id=TENANT,
        call=paused,
        actor_subject_id=ACTOR,
        reason="Review complete",
        now=NOW,
        request_id="resume",
        store=store,
    )
    cancelled = service.cancel(
        tenant_id=TENANT,
        call=resumed,
        actor_subject_id=ACTOR,
        reason="No longer required",
        now=NOW,
        request_id="cancel",
        store=store,
    )
    assert resumed.status is TrustedToolCallStatus.APPROVED
    assert cancelled.status is TrustedToolCallStatus.CANCELLED
    assert [item.revision for item in store.events] == [3, 4, 5]


@pytest.mark.parametrize(
    "status", [TrustedToolCallStatus.EXECUTING, TrustedToolCallStatus.VERIFYING]
)
def test_dispatched_call_cannot_be_paused_or_cancelled(status) -> None:
    service, store = TrustedToolControlService(), Store()
    with pytest.raises(ToolAlreadyDispatched):
        service.pause(
            tenant_id=TENANT,
            call=call(status),
            actor_subject_id=ACTOR,
            reason="stop",
            now=NOW,
            request_id="pause",
            store=store,
        )
    with pytest.raises(ToolAlreadyDispatched):
        service.cancel(
            tenant_id=TENANT,
            call=call(status),
            actor_subject_id=ACTOR,
            reason="stop",
            now=NOW,
            request_id="cancel",
            store=store,
        )


def test_resume_without_trusted_pause_event_fails_closed() -> None:
    with pytest.raises(ToolControlError, match="resume state"):
        TrustedToolControlService().resume(
            tenant_id=TENANT,
            call=call(TrustedToolCallStatus.PAUSED),
            actor_subject_id=ACTOR,
            reason="resume",
            now=NOW,
            request_id="resume",
            store=Store(),
        )


def test_emergency_stop_updates_global_control_and_only_pre_dispatch_calls() -> None:
    pending = call(TrustedToolCallStatus.APPROVED)
    dispatched = call(TrustedToolCallStatus.EXECUTING, call_id=UUID(int=1710))
    store = Store((pending, dispatched))
    changed = TrustedToolControlService().set_global(
        tenant_id=TENANT,
        actor_subject_id=ACTOR,
        automation_enabled=False,
        emergency_stop_active=True,
        reason="Containment emergency",
        now=NOW,
        store=store,
    )
    assert changed.emergency_stop_active is True
    assert store.calls[0].status is TrustedToolCallStatus.EMERGENCY_STOPPED
    assert store.calls[1].status is TrustedToolCallStatus.EXECUTING


def test_global_control_revision_is_monotonic() -> None:
    store, service = Store(), TrustedToolControlService()
    first = service.set_global(
        tenant_id=TENANT,
        actor_subject_id=ACTOR,
        automation_enabled=False,
        emergency_stop_active=False,
        reason="maintenance",
        now=NOW,
        store=store,
    )
    second = service.set_global(
        tenant_id=TENANT,
        actor_subject_id=ACTOR,
        automation_enabled=True,
        emergency_stop_active=False,
        reason="maintenance complete",
        now=NOW,
        store=store,
    )
    assert (first.revision, second.revision) == (0, 1)
