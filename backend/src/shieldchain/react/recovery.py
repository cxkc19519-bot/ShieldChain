"""Crash recovery decisions for stale controlled ReAct loops."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from shieldchain.react.domain import ReactLoop, ReactLoopStatus
from shieldchain.tools.execution import RecoveryDecision, RecoveryDisposition


class ReactRecoveryDisposition(StrEnum):
    RESUME_STEP = "resume_step"
    QUERY_TOOL_STATUS = "query_tool_status"
    RETRY_READ_ONLY = "retry_read_only"
    VERIFY_TOOL_RESULT = "verify_tool_result"
    WAIT_FOR_APPROVAL = "wait_for_approval"
    MANUAL_REVIEW = "manual_review"


@dataclass(frozen=True, slots=True)
class ReactRecoveryDecision:
    loop_id: UUID
    disposition: ReactRecoveryDisposition
    reason_code: str


class ReactRecoveryService:
    def decide(self, *, loop: ReactLoop, tool: RecoveryDecision | None) -> ReactRecoveryDecision:
        if not isinstance(loop, ReactLoop):
            raise TypeError("loop must be a ReactLoop")
        if loop.status is not ReactLoopStatus.RUNNING:
            return ReactRecoveryDecision(
                loop.id, ReactRecoveryDisposition.MANUAL_REVIEW, "loop_state_not_recoverable"
            )
        if tool is None:
            return ReactRecoveryDecision(
                loop.id, ReactRecoveryDisposition.RESUME_STEP, "stale_step_can_resume"
            )
        mapping = {
            RecoveryDisposition.QUERY_STATUS: ReactRecoveryDisposition.QUERY_TOOL_STATUS,
            RecoveryDisposition.RETRY_SAFE: ReactRecoveryDisposition.RETRY_READ_ONLY,
            RecoveryDisposition.VERIFY_RESULT: ReactRecoveryDisposition.VERIFY_TOOL_RESULT,
            RecoveryDisposition.WAIT_FOR_APPROVAL: ReactRecoveryDisposition.WAIT_FOR_APPROVAL,
            RecoveryDisposition.MANUAL_REVIEW: ReactRecoveryDisposition.MANUAL_REVIEW,
        }
        return ReactRecoveryDecision(loop.id, mapping[tool.disposition], tool.reason)
