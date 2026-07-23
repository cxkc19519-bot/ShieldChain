"""Tenant-scoped, append-only repository for trusted tool calls."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.incidents.persistence import EvidenceRecordRow, InvestigationRunRow
from shieldchain.incidents.repositories import append_incident_audit
from shieldchain.tools.domain import (
    ApprovalDecision,
    PolicyDecision,
    PolicyReason,
    ToolExecutionAttempt,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
)
from shieldchain.tools.persistence import (
    ToolApprovalRow,
    ToolExecutionAttemptRow,
    ToolPolicyDecisionRow,
    ToolVerificationRow,
    TrustedToolCallRow,
)
from shieldchain.tools.registry import BoundToolRequest


class TrustedToolCallNotFound(RuntimeError):
    pass


class TrustedToolIdempotencyConflict(RuntimeError):
    pass


class StaleTrustedToolCall(RuntimeError):
    pass


class InvalidToolEvidence(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _reference(value: dict[str, object]) -> EvidenceReference:
    if value.get("kind") != "evidence":
        raise InvalidToolEvidence("stored tool evidence kind is unsupported")
    return EvidenceReference(
        UUID(str(value["id"])),
        UUID(str(value["case_id"])),
        str(value["source_id"]),
        datetime.fromisoformat(str(value["observed_at"])),
        str(value["integrity_sha256"]),
    )


def _call(row: TrustedToolCallRow) -> TrustedToolCall:
    request = TrustedToolRequest(
        UUID(row.id),
        UUID(row.case_id),
        UUID(row.run_id),
        UUID(row.plan_id),
        row.idempotency_key,
        AgentRole(row.caller_role),
        row.tool_name,
        row.tool_version,
        dict(row.arguments_json),
        dict(row.expected_state_json),
        row.rollback_strategy,
        tuple(_reference(item) for item in row.evidence_json),
        _utc(row.created_at),
    )
    if request.request_digest != row.request_digest:
        raise TrustedToolIdempotencyConflict("stored request digest does not match payload")
    return TrustedToolCall(
        request,
        TrustedToolCallStatus(row.status),
        row.revision,
        PolicyReason(row.reason) if row.reason else None,
        _utc(row.updated_at),
    )


class SqlAlchemyTrustedToolRepository:
    def create_or_get(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        bound: BoundToolRequest,
        request_id: str,
    ) -> tuple[TrustedToolCall, bool]:
        request = bound.request
        run = session.execute(
            select(InvestigationRunRow).where(
                InvestigationRunRow.id == str(request.run_id),
                InvestigationRunRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if run is None or run.incident_id != str(request.case_id):
            raise TrustedToolCallNotFound("run not found in tenant")
        existing = session.execute(
            select(TrustedToolCallRow).where(
                TrustedToolCallRow.tenant_id == str(tenant_id),
                TrustedToolCallRow.run_id == str(request.run_id),
                TrustedToolCallRow.tool_name == request.tool_name,
                TrustedToolCallRow.idempotency_key == request.idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.request_digest != bound.request_digest:
                raise TrustedToolIdempotencyConflict("idempotency key is bound to another request")
            return _call(existing), False
        self._validate_evidence(session, request)
        row = TrustedToolCallRow(
            id=str(request.id),
            run_id=str(request.run_id),
            tenant_id=str(tenant_id),
            case_id=str(request.case_id),
            plan_id=str(request.plan_id),
            idempotency_key=request.idempotency_key,
            caller_role=request.caller_role.value,
            tool_name=request.tool_name,
            tool_version=request.tool_version,
            arguments_json=dict(request.arguments),
            expected_state_json=dict(request.expected_state),
            rollback_strategy=request.rollback_strategy,
            evidence_json=[item.to_dict() for item in request.evidence],
            request_digest=bound.request_digest,
            status=TrustedToolCallStatus.PROPOSED.value,
            revision=0,
            reason=None,
            created_at=request.created_at,
            updated_at=request.created_at,
        )
        session.add(row)
        append_incident_audit(
            session,
            incident_id=request.case_id,
            run_id=request.run_id,
            event_type="trusted_tool_call_proposed",
            request_id=request_id,
            occurred_at=request.created_at,
            payload={
                "tool_call_id": str(request.id),
                "tool": request.tool_name,
                "version": request.tool_version,
            },
        )
        session.flush()
        return _call(row), True

    def get(
        self, session: Session, *, tenant_id: UUID, tool_call_id: UUID
    ) -> TrustedToolCall | None:
        row = session.execute(
            select(TrustedToolCallRow).where(
                TrustedToolCallRow.id == str(tool_call_id),
                TrustedToolCallRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        return _call(row) if row else None

    def transition(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        current: TrustedToolCall,
        target: TrustedToolCallStatus,
        now: datetime,
        request_id: str,
        reason: PolicyReason | None = None,
    ) -> TrustedToolCall:
        changed = current.transition(target, now=now, reason=reason)
        result = session.execute(
            update(TrustedToolCallRow)
            .where(
                TrustedToolCallRow.id == str(current.request.id),
                TrustedToolCallRow.tenant_id == str(tenant_id),
                TrustedToolCallRow.revision == current.revision,
                TrustedToolCallRow.status == current.status.value,
            )
            .values(
                status=changed.status.value,
                revision=changed.revision,
                reason=changed.reason.value if changed.reason else None,
                updated_at=changed.updated_at,
            )
        )
        if result.rowcount != 1:
            raise StaleTrustedToolCall("trusted tool call revision is stale")
        append_incident_audit(
            session,
            incident_id=current.request.case_id,
            run_id=current.request.run_id,
            event_type="trusted_tool_call_transitioned",
            request_id=request_id,
            occurred_at=now,
            payload={
                "tool_call_id": str(current.request.id),
                "from": current.status.value,
                "to": target.value,
            },
        )
        return changed

    def append_policy(self, session: Session, *, tenant_id: UUID, decision: PolicyDecision) -> None:
        self._require_call(session, tenant_id, decision.request_id)
        session.add(
            ToolPolicyDecisionRow(
                id=str(uuid4()),
                tool_call_id=str(decision.request_id),
                tenant_id=str(tenant_id),
                outcome=decision.outcome.value,
                reason=decision.reason.value,
                policy_version=decision.policy_version,
                assessed_risk=decision.assessed_risk.value,
                created_at=decision.created_at,
                expires_at=decision.expires_at,
            )
        )

    def append_approval(
        self, session: Session, *, tenant_id: UUID, decision: ApprovalDecision
    ) -> None:
        self._require_call(session, tenant_id, decision.request_id)
        session.add(
            ToolApprovalRow(
                id=str(decision.id),
                tool_call_id=str(decision.request_id),
                tenant_id=str(tenant_id),
                request_digest=decision.request_digest,
                outcome=decision.outcome.value,
                approver_subject_id=str(decision.approver_subject_id),
                policy_version=decision.policy_version,
                reason_summary=decision.reason_summary,
                decided_at=decision.decided_at,
                expires_at=decision.expires_at,
            )
        )

    def append_attempt(
        self, session: Session, *, tenant_id: UUID, attempt: ToolExecutionAttempt
    ) -> None:
        call = self._require_call(session, tenant_id, attempt.request_id)
        session.add(
            ToolExecutionAttemptRow(
                id=str(attempt.id),
                tool_call_id=str(attempt.request_id),
                tenant_id=str(tenant_id),
                attempt_number=attempt.attempt_number,
                outcome=attempt.outcome.value,
                result_summary=attempt.result_summary,
                error_category=attempt.error_category,
                started_at=attempt.started_at,
                completed_at=attempt.completed_at,
            )
        )
        append_incident_audit(
            session,
            incident_id=UUID(call.case_id),
            run_id=UUID(call.run_id),
            event_type=(
                "trusted_tool_execution_retried"
                if attempt.attempt_number > 1
                else "trusted_tool_execution_attempted"
            ),
            request_id=f"tool-attempt:{attempt.id}",
            occurred_at=attempt.completed_at,
            payload={
                "tool_call_id": str(attempt.request_id),
                "attempt_number": attempt.attempt_number,
                "outcome": attempt.outcome.value,
            },
        )

    def append_verification(
        self, session: Session, *, tenant_id: UUID, verification: ToolVerification
    ) -> None:
        self._require_call(session, tenant_id, verification.request_id)
        session.add(
            ToolVerificationRow(
                id=str(verification.id),
                tool_call_id=str(verification.request_id),
                tenant_id=str(tenant_id),
                outcome=verification.outcome.value,
                observed_state_json=dict(verification.observed_state),
                evidence_json=[item.to_dict() for item in verification.evidence],
                reason=verification.reason.value if verification.reason else None,
                verified_at=verification.verified_at,
            )
        )

    @staticmethod
    def _require_call(session: Session, tenant_id: UUID, call_id: UUID) -> TrustedToolCallRow:
        found = session.execute(
            select(TrustedToolCallRow).where(
                TrustedToolCallRow.id == str(call_id),
                TrustedToolCallRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if found is None:
            raise TrustedToolCallNotFound("trusted tool call not found in tenant")
        return found

    @staticmethod
    def _validate_evidence(session: Session, request: TrustedToolRequest) -> None:
        for reference in request.evidence:
            if not isinstance(reference, EvidenceReference):
                raise InvalidToolEvidence("tool execution currently requires incident evidence")
            row = session.execute(
                select(EvidenceRecordRow).where(
                    EvidenceRecordRow.id == str(reference.id),
                    EvidenceRecordRow.run_id == str(request.run_id),
                )
            ).scalar_one_or_none()
            if (
                row is None
                or row.integrity_sha256 != reference.integrity_sha256
                or not row.confirmed
            ):
                raise InvalidToolEvidence("tool evidence is missing, unconfirmed, or invalid")
