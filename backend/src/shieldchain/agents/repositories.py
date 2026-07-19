"""Fail-closed SQLAlchemy repository for multi-agent context."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from shieldchain.agents.domain import (
    AgentOutput,
    AgentPrivateContext,
    AgentRole,
    AlertTriagePrivateContext,
    BudgetSnapshot,
    CasePhase,
    ConfirmedFact,
    EvidenceReference,
    HandoffPacket,
    Hypothesis,
    KnowledgeReference,
    KnowledgeRetrievalPrivateContext,
    Reference,
    ReportingPrivateContext,
    ResponsePlanningPrivateContext,
    Risk,
    SharedCaseContext,
    SuperagentPrivateContext,
    ThreatInvestigationPrivateContext,
    VerificationPrivateContext,
)
from shieldchain.agents.persistence import (
    AgentExecutionRow,
    AgentHandoffRow,
    AgentPrivateContextRow,
    CaseContextRow,
    ConfirmedCaseFactRow,
)
from shieldchain.agents.ports import (
    AgentContextAlreadyExists,
    AgentContextNotFound,
    AgentRunNotFound,
    InvalidTrustedReference,
    PrivateContextAccessDenied,
    StaleContextRevision,
    VersionedPrivateContext,
)
from shieldchain.incidents.persistence import EvidenceRecordRow, InvestigationRunRow
from shieldchain.incidents.repositories import append_incident_audit
from shieldchain.rag.domain import AccessScope, SensitivityLevel
from shieldchain.rag.persistence import (
    DocumentVersionRow,
    KnowledgeChunkRow,
    KnowledgeDocumentRow,
)

_PRIVATE_TYPES = {
    AgentRole.SUPERAGENT: SuperagentPrivateContext,
    AgentRole.ALERT_TRIAGE: AlertTriagePrivateContext,
    AgentRole.THREAT_INVESTIGATION: ThreatInvestigationPrivateContext,
    AgentRole.KNOWLEDGE_RETRIEVAL: KnowledgeRetrievalPrivateContext,
    AgentRole.RESPONSE_PLANNING: ResponsePlanningPrivateContext,
    AgentRole.VERIFICATION: VerificationPrivateContext,
    AgentRole.REPORTING: ReportingPrivateContext,
}


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _reference(value: dict[str, Any]) -> Reference:
    kind = value.get("kind")
    if kind == "evidence":
        cls = EvidenceReference
    elif kind == "knowledge":
        cls = KnowledgeReference
    else:
        raise InvalidTrustedReference("stored reference kind is invalid")
    return cls(
        id=UUID(value["id"]),
        case_id=UUID(value["case_id"]),
        source_id=value["source_id"],
        observed_at=datetime.fromisoformat(value["observed_at"]),
        integrity_sha256=value["integrity_sha256"],
    )


def _references(values: list[dict[str, Any]]) -> tuple[Reference, ...]:
    return tuple(_reference(value) for value in values)


def _hypothesis(value: dict[str, Any]) -> Hypothesis:
    return Hypothesis(
        UUID(value["id"]), value["statement"], value["confidence"], _references(value["references"])
    )


def _risk(value: dict[str, Any]) -> Risk:
    return Risk(
        UUID(value["id"]), value["description"], value["severity"], _references(value["references"])
    )


class SqlAlchemyAgentContextRepository:
    """All reads are scoped in SQL by trusted tenant and run identifiers."""

    def create_shared(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        context: SharedCaseContext,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> SharedCaseContext:
        run = self._run(session, tenant_id, run_id)
        if context.case_id != UUID(run.incident_id) or context.revision != 0:
            raise AgentContextNotFound("case/run mismatch or initial revision is not zero")
        self._validate_references(
            session, run, context.case_id, self._context_refs(context), knowledge_scope
        )
        self._begin_sqlite(session)
        with session.begin_nested():
            row = CaseContextRow(
                id=str(run_id),
                run_id=str(run_id),
                tenant_id=str(tenant_id),
                revision=0,
                phase=context.phase.value,
                user_goal=context.user_goal,
                hypotheses_json=[x.to_dict() for x in context.hypotheses],
                risks_json=[x.to_dict() for x in context.risks],
                plan_json=list(context.plan),
                step_status_json=dict(context.step_status),
                disposition_status=context.disposition_status,
                budget_json=context.budget.to_dict(),
                created_at=context.updated_at,
                updated_at=context.updated_at,
            )
            session.add(row)
            for fact in context.confirmed_facts:
                session.add(self._fact_row(fact, tenant_id, run_id))
            try:
                session.flush()
            except IntegrityError as error:
                message = str(error.orig)
                constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
                if constraint in {"case_contexts_pkey", "uq_case_context_run"} or (
                    "case_contexts.id" in message or "case_contexts.run_id" in message
                ):
                    raise AgentContextAlreadyExists("shared context already exists") from None
                raise
            self._audit(
                session,
                run,
                run_id,
                "agent_context_created",
                request_id,
                context.updated_at,
                {"revision": 0},
            )
            session.flush()
        return context

    def get_shared(
        self, session: Session, *, tenant_id: UUID, run_id: UUID
    ) -> SharedCaseContext | None:
        row = session.execute(
            select(CaseContextRow).where(
                CaseContextRow.tenant_id == str(tenant_id), CaseContextRow.run_id == str(run_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        run = self._run(session, tenant_id, run_id)
        facts = tuple(
            session.execute(
                select(ConfirmedCaseFactRow)
                .where(
                    ConfirmedCaseFactRow.tenant_id == str(tenant_id),
                    ConfirmedCaseFactRow.case_context_id == row.id,
                )
                .order_by(ConfirmedCaseFactRow.created_at, ConfirmedCaseFactRow.id)
            ).scalars()
        )
        return SharedCaseContext(
            case_id=UUID(run.incident_id),
            phase=CasePhase(row.phase),
            user_goal=row.user_goal,
            confirmed_facts=tuple(self._fact(value) for value in facts),
            hypotheses=tuple(_hypothesis(value) for value in row.hypotheses_json),
            risks=tuple(_risk(value) for value in row.risks_json),
            plan=tuple(row.plan_json),
            step_status=dict(row.step_status_json),
            disposition_status=row.disposition_status,
            budget=BudgetSnapshot(**row.budget_json),
            revision=row.revision,
            updated_at=_utc(row.updated_at),
        )

    def update_shared(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        context: SharedCaseContext,
        expected_revision: int,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> SharedCaseContext:
        run = self._run(session, tenant_id, run_id)
        if context.case_id != UUID(run.incident_id):
            raise AgentContextNotFound("case/run mismatch")
        self._validate_references(
            session, run, context.case_id, self._context_refs(context), knowledge_scope
        )
        self._begin_sqlite(session)
        with session.begin_nested():
            result = session.execute(
                update(CaseContextRow)
                .where(
                    CaseContextRow.tenant_id == str(tenant_id),
                    CaseContextRow.run_id == str(run_id),
                    CaseContextRow.id == str(run_id),
                    CaseContextRow.revision == expected_revision,
                )
                .values(
                    phase=context.phase.value,
                    hypotheses_json=[x.to_dict() for x in context.hypotheses],
                    risks_json=[x.to_dict() for x in context.risks],
                    plan_json=list(context.plan),
                    step_status_json=dict(context.step_status),
                    disposition_status=context.disposition_status,
                    budget_json=context.budget.to_dict(),
                    revision=expected_revision + 1,
                    updated_at=context.updated_at,
                )
            )
            if result.rowcount != 1:
                raise StaleContextRevision(f"expected shared revision {expected_revision}")
            self._audit(
                session,
                run,
                run_id,
                "agent_context_updated",
                request_id,
                context.updated_at,
                {"from_revision": expected_revision, "to_revision": expected_revision + 1},
            )
            session.flush()
        stored = self.get_shared(session, tenant_id=tenant_id, run_id=run_id)
        assert stored is not None
        return stored

    def append_fact(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        fact: ConfirmedFact,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None:
        run = self._run(session, tenant_id, run_id)
        if fact.references[0].case_id != UUID(run.incident_id):
            raise InvalidTrustedReference("fact belongs to a different case")
        self._validate_references(
            session, run, UUID(run.incident_id), tuple(fact.references), knowledge_scope
        )
        case = self._case(session, tenant_id, run_id)
        self._begin_sqlite(session)
        with session.begin_nested():
            session.add(self._fact_row(fact, tenant_id, UUID(case.id)))
            self._audit(
                session,
                run,
                run_id,
                "confirmed_fact_appended",
                request_id,
                fact.confirmed_at,
                {"fact_id": str(fact.id)},
            )
            session.flush()

    def get_private(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        acting_role: AgentRole,
        role: AgentRole,
    ) -> VersionedPrivateContext | None:
        if acting_role is not role:
            raise PrivateContextAccessDenied("a role may only read its own private context")
        row = session.execute(
            select(AgentPrivateContextRow).where(
                AgentPrivateContextRow.tenant_id == str(tenant_id),
                AgentPrivateContextRow.run_id == str(run_id),
                AgentPrivateContextRow.role == role.value,
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        cls = _PRIVATE_TYPES[role]
        context = cls(
            case_id=self._case_id(session, tenant_id, run_id),
            owner=role,
            working_items=dict(row.working_items_json),
            references=_references(row.references_json),
            updated_at=_utc(row.updated_at),
        )
        return VersionedPrivateContext(context, row.revision)

    def upsert_private(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        acting_role: AgentRole,
        context: AgentPrivateContext,
        expected_revision: int | None,
        knowledge_scope: AccessScope | None = None,
    ) -> VersionedPrivateContext:
        if acting_role is not context.owner:
            raise PrivateContextAccessDenied("a role may only write its own private context")
        run = self._run(session, tenant_id, run_id)
        if context.case_id != UUID(run.incident_id):
            raise AgentContextNotFound("case/run mismatch")
        self._validate_references(
            session, run, context.case_id, tuple(context.references), knowledge_scope
        )
        if expected_revision is None:
            existing = session.execute(
                select(AgentPrivateContextRow.id).where(
                    AgentPrivateContextRow.tenant_id == str(tenant_id),
                    AgentPrivateContextRow.run_id == str(run_id),
                    AgentPrivateContextRow.role == context.owner.value,
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise StaleContextRevision("private context already exists")
        self._begin_sqlite(session)
        with session.begin_nested():
            if expected_revision is None:
                row = AgentPrivateContextRow(
                    id=str(uuid4()),
                    run_id=str(run_id),
                    tenant_id=str(tenant_id),
                    role=context.owner.value,
                    revision=0,
                    working_items_json={k: list(v) for k, v in context.working_items.items()},
                    references_json=[x.to_dict() for x in context.references],
                    created_at=context.updated_at,
                    updated_at=context.updated_at,
                )
                session.add(row)
            else:
                result = session.execute(
                    update(AgentPrivateContextRow)
                    .where(
                        AgentPrivateContextRow.tenant_id == str(tenant_id),
                        AgentPrivateContextRow.run_id == str(run_id),
                        AgentPrivateContextRow.role == context.owner.value,
                        AgentPrivateContextRow.revision == expected_revision,
                    )
                    .values(
                        working_items_json={k: list(v) for k, v in context.working_items.items()},
                        references_json=[x.to_dict() for x in context.references],
                        revision=expected_revision + 1,
                        updated_at=context.updated_at,
                    )
                )
                if result.rowcount != 1:
                    raise StaleContextRevision(f"expected private revision {expected_revision}")
            try:
                session.flush()
            except IntegrityError as error:
                message = str(error.orig)
                constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
                if constraint == "uq_private_context_run_role" or (
                    "agent_private_contexts.run_id" in message
                ):
                    raise StaleContextRevision("private context already exists") from None
                raise
        stored = self.get_private(
            session, tenant_id=tenant_id, run_id=run_id, acting_role=acting_role, role=acting_role
        )
        assert stored is not None
        return stored

    def append_handoff(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        handoff: HandoffPacket,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None:
        run = self._run(session, tenant_id, run_id)
        if handoff.case_id != UUID(run.incident_id):
            raise AgentContextNotFound("case/run mismatch")
        self._validate_references(
            session, run, handoff.case_id, tuple(handoff.references), knowledge_scope
        )
        self._begin_sqlite(session)
        with session.begin_nested():
            session.add(
                AgentHandoffRow(
                    id=str(handoff.id),
                    run_id=str(run_id),
                    tenant_id=str(tenant_id),
                    sender_role=handoff.sender.value,
                    receiver_role=handoff.receiver.value,
                    conclusion=handoff.conclusion,
                    references_json=[x.to_dict() for x in handoff.references],
                    confidence=handoff.confidence,
                    open_questions_json=list(handoff.open_questions),
                    recommended_actions_json=list(handoff.recommended_actions),
                    created_at=handoff.created_at,
                )
            )
            self._audit(
                session,
                run,
                run_id,
                "agent_handoff_appended",
                request_id,
                handoff.created_at,
                {
                    "handoff_id": str(handoff.id),
                    "sender": handoff.sender.value,
                    "receiver": handoff.receiver.value,
                },
            )
            session.flush()

    def append_output(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        output: AgentOutput,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None:
        run = self._run(session, tenant_id, run_id)
        if output.case_id != UUID(run.incident_id):
            raise AgentContextNotFound("case/run mismatch")
        refs = tuple(output.references)
        for item in (*output.hypotheses, *output.risks):
            refs += tuple(item.references)
        self._validate_references(session, run, output.case_id, refs, knowledge_scope)
        execution_id = uuid4()
        self._begin_sqlite(session)
        with session.begin_nested():
            session.add(
                AgentExecutionRow(
                    id=str(execution_id),
                    run_id=str(run_id),
                    tenant_id=str(tenant_id),
                    role=output.role.value,
                    summary=output.summary,
                    references_json=[x.to_dict() for x in output.references],
                    hypotheses_json=[x.to_dict() for x in output.hypotheses],
                    risks_json=[x.to_dict() for x in output.risks],
                    recommended_actions_json=list(output.recommended_actions),
                    termination_reason=output.termination_reason.value,
                    created_at=output.created_at,
                )
            )
            self._audit(
                session,
                run,
                run_id,
                "agent_execution_appended",
                request_id,
                output.created_at,
                {
                    "execution_id": str(execution_id),
                    "role": output.role.value,
                    "termination_reason": output.termination_reason.value,
                },
            )
            session.flush()

    @staticmethod
    def _run(session: Session, tenant_id: UUID, run_id: UUID) -> InvestigationRunRow:
        row = session.execute(
            select(InvestigationRunRow).where(
                InvestigationRunRow.tenant_id == str(tenant_id),
                InvestigationRunRow.id == str(run_id),
            )
        ).scalar_one_or_none()
        if row is None:
            raise AgentRunNotFound(f"run not found in tenant: {run_id}")
        return row

    @staticmethod
    def _case(session: Session, tenant_id: UUID, run_id: UUID) -> CaseContextRow:
        row = session.execute(
            select(CaseContextRow).where(
                CaseContextRow.tenant_id == str(tenant_id), CaseContextRow.run_id == str(run_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise AgentContextNotFound(f"shared context not found: {run_id}")
        return row

    def _case_id(self, session: Session, tenant_id: UUID, run_id: UUID) -> UUID:
        self._case(session, tenant_id, run_id)
        return UUID(self._run(session, tenant_id, run_id).incident_id)

    @staticmethod
    def _context_refs(context: SharedCaseContext) -> tuple[Reference, ...]:
        refs: tuple[Reference, ...] = ()
        for item in (*context.confirmed_facts, *context.hypotheses, *context.risks):
            refs += tuple(item.references)
        return refs

    @staticmethod
    def _fact_row(fact: ConfirmedFact, tenant_id: UUID, case_id: UUID) -> ConfirmedCaseFactRow:
        return ConfirmedCaseFactRow(
            id=str(fact.id),
            case_context_id=str(case_id),
            tenant_id=str(tenant_id),
            statement=fact.statement,
            confirmed=True,
            references_json=[x.to_dict() for x in fact.references],
            confidence=fact.confidence,
            confirmed_at=fact.confirmed_at,
            created_at=fact.confirmed_at,
        )

    @staticmethod
    def _fact(row: ConfirmedCaseFactRow) -> ConfirmedFact:
        return ConfirmedFact(
            UUID(row.id),
            row.statement,
            row.confirmed,
            _references(row.references_json),
            row.confidence,
            _utc(row.confirmed_at),
        )

    @staticmethod
    def _validate_references(
        session: Session,
        run: InvestigationRunRow,
        case_id: UUID,
        references: tuple[Reference, ...],
        knowledge_scope: AccessScope | None,
    ) -> None:
        for reference in references:
            if reference.case_id != case_id:
                raise InvalidTrustedReference("reference belongs to a different case")
            if isinstance(reference, EvidenceReference):
                evidence = session.execute(
                    select(EvidenceRecordRow).where(
                        EvidenceRecordRow.id == str(reference.id),
                        EvidenceRecordRow.run_id == run.id,
                        EvidenceRecordRow.integrity_sha256 == reference.integrity_sha256,
                        EvidenceRecordRow.confirmed.is_(True),
                    )
                ).one_or_none()
                if evidence is None:
                    raise InvalidTrustedReference("evidence is absent, unconfirmed, or invalid")
            else:
                if knowledge_scope is None or str(knowledge_scope.tenant_id) != run.tenant_id:
                    raise InvalidTrustedReference(
                        "knowledge authorization scope is missing or invalid"
                    )
                knowledge = session.execute(
                    select(
                        KnowledgeDocumentRow.tenant_id,
                        KnowledgeDocumentRow.knowledge_base_id,
                        KnowledgeChunkRow.sensitivity,
                        KnowledgeChunkRow.permission_tags_json,
                    )
                    .join(
                        DocumentVersionRow,
                        DocumentVersionRow.id == KnowledgeChunkRow.document_version_id,
                    )
                    .join(
                        KnowledgeDocumentRow,
                        KnowledgeDocumentRow.id == DocumentVersionRow.document_id,
                    )
                    .where(
                        KnowledgeChunkRow.id == str(reference.id),
                        KnowledgeChunkRow.content_sha256 == reference.integrity_sha256,
                        KnowledgeDocumentRow.tenant_id == run.tenant_id,
                        KnowledgeDocumentRow.status == "published",
                        KnowledgeDocumentRow.current_version_id == DocumentVersionRow.id,
                        DocumentVersionRow.published_at.is_not(None),
                    )
                ).one_or_none()
                if knowledge is None:
                    raise InvalidTrustedReference("knowledge is absent, stale, or unpublished")
                stored_tenant, base_id, sensitivity, permission_tags = knowledge
                try:
                    allowed = knowledge_scope.allows(
                        UUID(stored_tenant),
                        UUID(base_id),
                        SensitivityLevel(sensitivity),
                        permission_tags,
                    )
                except (TypeError, ValueError):
                    allowed = False
                if not allowed:
                    raise InvalidTrustedReference("knowledge reference is not authorized")

    @staticmethod
    def _audit(
        session: Session,
        run: InvestigationRunRow,
        run_id: UUID,
        event_type: str,
        request_id: str,
        occurred_at: datetime,
        payload: dict[str, Any],
    ) -> None:
        append_incident_audit(
            session,
            incident_id=UUID(run.incident_id),
            run_id=run_id,
            event_type=event_type,
            request_id=request_id,
            occurred_at=occurred_at,
            payload=payload,
        )

    @staticmethod
    def _begin_sqlite(session: Session) -> None:
        connection = session.connection()
        if (
            connection.dialect.name == "sqlite"
            and not connection.connection.driver_connection.in_transaction
        ):
            connection.exec_driver_sql("BEGIN")


class SqlAlchemyAgentContextUnitOfWork:
    """Session adapter that fixes the trusted tenant/run boundary at construction."""

    def __init__(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        repository: SqlAlchemyAgentContextRepository | None = None,
    ) -> None:
        self._session = session
        self._tenant_id = tenant_id
        self._run_id = run_id
        self._repository = repository or SqlAlchemyAgentContextRepository()

    def get_shared(self) -> SharedCaseContext | None:
        return self._repository.get_shared(
            self._session, tenant_id=self._tenant_id, run_id=self._run_id
        )

    def create_shared(
        self,
        context: SharedCaseContext,
        *,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> SharedCaseContext:
        return self._repository.create_shared(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            context=context,
            request_id=request_id,
            knowledge_scope=knowledge_scope,
        )

    def update_shared(
        self,
        context: SharedCaseContext,
        *,
        expected_revision: int,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> SharedCaseContext:
        return self._repository.update_shared(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            context=context,
            expected_revision=expected_revision,
            request_id=request_id,
            knowledge_scope=knowledge_scope,
        )

    def append_fact(
        self, fact: ConfirmedFact, *, request_id: str, knowledge_scope: AccessScope | None = None
    ) -> None:
        self._repository.append_fact(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            fact=fact,
            request_id=request_id,
            knowledge_scope=knowledge_scope,
        )

    def get_private(self, role: AgentRole) -> VersionedPrivateContext | None:
        return self._repository.get_private(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            acting_role=role,
            role=role,
        )

    def upsert_private(
        self,
        context: AgentPrivateContext,
        *,
        expected_revision: int | None,
        knowledge_scope: AccessScope | None = None,
    ) -> VersionedPrivateContext:
        return self._repository.upsert_private(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            acting_role=context.owner,
            context=context,
            expected_revision=expected_revision,
            knowledge_scope=knowledge_scope,
        )

    def append_handoff(
        self, handoff: HandoffPacket, *, request_id: str, knowledge_scope: AccessScope | None = None
    ) -> None:
        self._repository.append_handoff(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            handoff=handoff,
            request_id=request_id,
            knowledge_scope=knowledge_scope,
        )

    def append_output(
        self, output: AgentOutput, *, request_id: str, knowledge_scope: AccessScope | None = None
    ) -> None:
        self._repository.append_output(
            self._session,
            tenant_id=self._tenant_id,
            run_id=self._run_id,
            output=output,
            request_id=request_id,
            knowledge_scope=knowledge_scope,
        )
