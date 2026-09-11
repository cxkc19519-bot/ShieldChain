"""CAS-based trusted-tool pause, cancellation, and global controls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from shieldchain.tools.domain import TrustedToolCall, TrustedToolCallStatus


class ToolControlAction(StrEnum):
    PAUSE = "pause"
    RESUME = "resume"
    CANCEL = "cancel"
    AUTOMATION_ENABLED = "automation_enabled"
    AUTOMATION_DISABLED = "automation_disabled"
    EMERGENCY_STOP = "emergency_stop"
    EMERGENCY_CLEARED = "emergency_cleared"


@dataclass(frozen=True, slots=True)
class AutomationControl:
    tenant_id: UUID
    automation_enabled: bool
    emergency_stop_active: bool
    revision: int
    actor_subject_id: UUID
    reason: str
    updated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID) or not isinstance(self.actor_subject_id, UUID):
            raise TypeError("control identifiers must be UUID values")
        if self.revision < 0:
            raise ValueError("control revision must be non-negative")
        if not self.reason.strip() or len(self.reason.strip()) > 512:
            raise ValueError("control reason is invalid")
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() != timedelta(0):
            raise ValueError("updated_at must be an aware UTC datetime")


@dataclass(frozen=True, slots=True)
class ToolControlEvent:
    id: UUID
    tenant_id: UUID
    request_id: UUID | None
    action: ToolControlAction
    actor_subject_id: UUID
    reason: str
    previous_status: TrustedToolCallStatus | None
    new_status: TrustedToolCallStatus | None
    revision: int
    occurred_at: datetime


class ToolControlError(RuntimeError):
    pass


class ToolAlreadyDispatched(ToolControlError):
    pass


class ToolControlStore(Protocol):
    def transition_controlled_call(
        self,
        *,
        tenant_id: UUID,
        current: TrustedToolCall,
        target: TrustedToolCallStatus,
        now: datetime,
        request_id: str,
    ) -> TrustedToolCall: ...

    def append_control_event(self, event: ToolControlEvent) -> None: ...

    def latest_call_event(
        self, *, tenant_id: UUID, request_id: UUID
    ) -> ToolControlEvent | None: ...

    def get_control(self, *, tenant_id: UUID) -> AutomationControl | None: ...

    def set_control(
        self, *, current: AutomationControl | None, changed: AutomationControl
    ) -> AutomationControl: ...

    def pending_calls(self, *, tenant_id: UUID) -> tuple[TrustedToolCall, ...]: ...


class TrustedToolControlService:
    _CONTROLLABLE = frozenset(
        {
            TrustedToolCallStatus.PROPOSED,
            TrustedToolCallStatus.POLICY_CHECKED,
            TrustedToolCallStatus.AWAITING_APPROVAL,
            TrustedToolCallStatus.APPROVED,
        }
    )

    def pause(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        actor_subject_id: UUID,
        reason: str,
        now: datetime,
        request_id: str,
        store: ToolControlStore,
    ) -> TrustedToolCall:
        if call.status in {TrustedToolCallStatus.EXECUTING, TrustedToolCallStatus.VERIFYING}:
            raise ToolAlreadyDispatched("dispatched calls must be queried and verified")
        if call.status not in self._CONTROLLABLE:
            raise ToolControlError("tool call cannot be paused in its current state")
        return self._transition(
            tenant_id,
            call,
            TrustedToolCallStatus.PAUSED,
            actor_subject_id,
            reason,
            now,
            request_id,
            ToolControlAction.PAUSE,
            store,
        )

    def resume(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        actor_subject_id: UUID,
        reason: str,
        now: datetime,
        request_id: str,
        store: ToolControlStore,
    ) -> TrustedToolCall:
        if call.status is not TrustedToolCallStatus.PAUSED:
            raise ToolControlError("only paused calls can be resumed")
        previous = store.latest_call_event(tenant_id=tenant_id, request_id=call.request.id)
        if (
            previous is None
            or previous.action is not ToolControlAction.PAUSE
            or previous.previous_status not in self._CONTROLLABLE
        ):
            raise ToolControlError("paused call has no trusted resume state")
        return self._transition(
            tenant_id,
            call,
            previous.previous_status,
            actor_subject_id,
            reason,
            now,
            request_id,
            ToolControlAction.RESUME,
            store,
        )

    def cancel(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        actor_subject_id: UUID,
        reason: str,
        now: datetime,
        request_id: str,
        store: ToolControlStore,
    ) -> TrustedToolCall:
        if call.status in {TrustedToolCallStatus.EXECUTING, TrustedToolCallStatus.VERIFYING}:
            raise ToolAlreadyDispatched("dispatched calls cannot be represented as cancelled")
        if call.status not in self._CONTROLLABLE | {TrustedToolCallStatus.PAUSED}:
            raise ToolControlError("tool call cannot be cancelled in its current state")
        return self._transition(
            tenant_id,
            call,
            TrustedToolCallStatus.CANCELLED,
            actor_subject_id,
            reason,
            now,
            request_id,
            ToolControlAction.CANCEL,
            store,
        )

    def set_global(
        self,
        *,
        tenant_id: UUID,
        actor_subject_id: UUID,
        automation_enabled: bool,
        emergency_stop_active: bool,
        reason: str,
        now: datetime,
        store: ToolControlStore,
    ) -> AutomationControl:
        current = store.get_control(tenant_id=tenant_id)
        changed = AutomationControl(
            tenant_id,
            automation_enabled,
            emergency_stop_active,
            0 if current is None else current.revision + 1,
            actor_subject_id,
            reason,
            now,
        )
        saved = store.set_control(current=current, changed=changed)
        action = (
            ToolControlAction.EMERGENCY_STOP
            if emergency_stop_active
            else ToolControlAction.AUTOMATION_ENABLED
            if automation_enabled
            else ToolControlAction.AUTOMATION_DISABLED
        )
        store.append_control_event(
            ToolControlEvent(
                uuid4(),
                tenant_id,
                None,
                action,
                actor_subject_id,
                reason,
                None,
                None,
                saved.revision,
                now,
            )
        )
        if emergency_stop_active:
            for call in store.pending_calls(tenant_id=tenant_id):
                self._transition(
                    tenant_id,
                    call,
                    TrustedToolCallStatus.EMERGENCY_STOPPED,
                    actor_subject_id,
                    reason,
                    now,
                    f"emergency-stop:{call.request.id}",
                    action,
                    store,
                )
        return saved

    @staticmethod
    def _transition(
        tenant_id: UUID,
        call: TrustedToolCall,
        target: TrustedToolCallStatus,
        actor_subject_id: UUID,
        reason: str,
        now: datetime,
        request_id: str,
        action: ToolControlAction,
        store: ToolControlStore,
    ) -> TrustedToolCall:
        changed = store.transition_controlled_call(
            tenant_id=tenant_id, current=call, target=target, now=now, request_id=request_id
        )
        store.append_control_event(
            ToolControlEvent(
                uuid4(),
                tenant_id,
                call.request.id,
                action,
                actor_subject_id,
                reason,
                call.status,
                changed.status,
                changed.revision,
                now,
            )
        )
        return changed
