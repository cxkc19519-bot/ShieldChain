from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from shieldchain.agents.domain import (
    AgentOutput,
    AgentRole,
    AlertTriagePrivateContext,
    BudgetSnapshot,
    CasePhase,
    ConfirmedFact,
    EvidenceReference,
    HandoffPacket,
    KnowledgeReference,
    SharedCaseContext,
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
    AgentRunNotFound,
    InvalidTrustedReference,
    PrivateContextAccessDenied,
    StaleContextRevision,
)
from shieldchain.agents.repositories import SqlAlchemyAgentContextRepository
from shieldchain.db.base import Base
from shieldchain.incidents.persistence import (
    AuditEventRow,
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.rag.domain import AccessScope, SensitivityLevel
from shieldchain.rag.persistence import (
    DocumentVersionRow,
    KnowledgeBaseRow,
    KnowledgeChunkRow,
    KnowledgeDocumentRow,
)

NOW = datetime(2026, 7, 20, 1, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
OTHER = UUID("00000000-0000-4000-8000-000000000099")
CASE = UUID(int=201)
RUN = UUID(int=301)
EVIDENCE = UUID(int=401)
CHUNK = UUID(int=501)
SHA = "a" * 64


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(
            SimulationInstanceRow(
                id=str(UUID(int=101)),
                scenario_key="phishing",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        value.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="INC",
                simulation_instance_id=str(UUID(int=101)),
                alert_id="ALT",
                alert_status="open",
                endpoint="host",
                username="user",
                source_ip="10.0.0.1",
                remote_ip="203.0.113.1",
                remote_port=443,
                process_name="p",
                parent_process_name="pp",
                command_summary="cmd",
                threat_label="threat",
                created_at=NOW,
            )
        )
        value.flush()
        value.add(
            InvestigationRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                incident_id=str(CASE),
                simulation_instance_id=str(UUID(int=101)),
                status="pending",
                mode="normal",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        value.flush()
        value.add(
            EvidenceRecordRow(
                id=str(EVIDENCE),
                run_id=str(RUN),
                evidence_type="alert",
                source="siem",
                observed_at=NOW,
                summary="confirmed",
                raw_reference="siem:1",
                integrity_sha256=SHA,
                confidence=1.0,
                confirmed=True,
                payload_json={},
                created_at=NOW,
            )
        )
        value.commit()
        yield value
    engine.dispose()


def budget() -> BudgetSnapshot:
    return BudgetSnapshot(10, 0, 2, 0, 60, 0, 1000, 0, 1.0, 0.0, 5, 0)


def shared() -> SharedCaseContext:
    return SharedCaseContext(
        CASE,
        CasePhase.TRIAGE,
        "investigate",
        (),
        (),
        (),
        ("triage",),
        {"triage": "pending"},
        "open",
        budget(),
        0,
        NOW,
    )


def evidence_ref(**changes: object) -> EvidenceReference:
    values = dict(
        id=EVIDENCE, case_id=CASE, source_id="siem:1", observed_at=NOW, integrity_sha256=SHA
    )
    values.update(changes)
    return EvidenceReference(**values)


def test_shared_and_private_cas_happy_path_and_audit(session: Session) -> None:
    repo = SqlAlchemyAgentContextRepository()
    assert (
        repo.create_shared(
            session, tenant_id=TENANT, run_id=RUN, context=shared(), request_id="create"
        ).revision
        == 0
    )
    with pytest.raises(AgentContextAlreadyExists):
        repo.create_shared(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            context=shared(),
            request_id="duplicate",
        )
    changed = replace(shared(), phase=CasePhase.INVESTIGATION, plan=("investigate",))
    assert (
        repo.update_shared(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            context=changed,
            expected_revision=0,
            request_id="update",
        ).revision
        == 1
    )
    private = AlertTriagePrivateContext(
        CASE, AgentRole.ALERT_TRIAGE, {"todo": ("x",)}, (evidence_ref(),), NOW
    )
    assert (
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=private,
            expected_revision=None,
        ).revision
        == 0
    )
    with pytest.raises(StaleContextRevision, match="already exists"):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=private,
            expected_revision=None,
        )
    assert (
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=private,
            expected_revision=0,
        ).revision
        == 1
    )
    assert session.scalar(select(func.count()).select_from(AuditEventRow)) == 2


def test_tenant_role_revision_and_forged_evidence_fail_closed(session: Session) -> None:
    repo = SqlAlchemyAgentContextRepository()
    repo.create_shared(session, tenant_id=TENANT, run_id=RUN, context=shared(), request_id="c")
    assert repo.get_shared(session, tenant_id=OTHER, run_id=RUN) is None
    with pytest.raises(AgentRunNotFound):
        repo.update_shared(
            session,
            tenant_id=OTHER,
            run_id=RUN,
            context=shared(),
            expected_revision=0,
            request_id="cross-tenant",
        )
    with pytest.raises(StaleContextRevision):
        repo.update_shared(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            context=shared(),
            expected_revision=9,
            request_id="stale",
        )
    private = AlertTriagePrivateContext(CASE, AgentRole.ALERT_TRIAGE, {}, (), NOW)
    with pytest.raises(PrivateContextAccessDenied):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.REPORTING,
            context=private,
            expected_revision=None,
        )
    forged = AlertTriagePrivateContext(
        CASE, AgentRole.ALERT_TRIAGE, {}, (evidence_ref(integrity_sha256="b" * 64),), NOW
    )
    with pytest.raises(InvalidTrustedReference):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=forged,
            expected_revision=None,
        )
    evidence = session.get(EvidenceRecordRow, str(EVIDENCE))
    assert evidence is not None
    evidence.confirmed = False
    unconfirmed = AlertTriagePrivateContext(
        CASE, AgentRole.ALERT_TRIAGE, {}, (evidence_ref(),), NOW
    )
    with pytest.raises(InvalidTrustedReference, match="unconfirmed"):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=unconfirmed,
            expected_revision=None,
        )
    other_run = uuid4()
    session.add(
        InvestigationRunRow(
            id=str(other_run),
            tenant_id=str(TENANT),
            incident_id=str(CASE),
            simulation_instance_id=str(UUID(int=101)),
            status="closed",
            mode="normal",
            created_at=NOW,
            updated_at=NOW,
            completed_at=NOW,
        )
    )
    session.flush()
    evidence.confirmed = True
    evidence.run_id = str(other_run)
    session.flush()
    with pytest.raises(InvalidTrustedReference):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=unconfirmed,
            expected_revision=None,
        )


def test_knowledge_reference_requires_tenant_current_published_and_sha(session: Session) -> None:
    repo = SqlAlchemyAgentContextRepository()
    repo.create_shared(session, tenant_id=TENANT, run_id=RUN, context=shared(), request_id="c")
    base_id, doc_id, version_id = uuid4(), uuid4(), uuid4()
    session.add(
        KnowledgeBaseRow(
            id=str(base_id),
            tenant_id=str(TENANT),
            name="kb",
            status="published",
            default_sensitivity="internal",
            version_policy="manual",
            created_at=NOW,
            updated_at=NOW,
        )
    )
    session.add(
        KnowledgeDocumentRow(
            id=str(doc_id),
            knowledge_base_id=str(base_id),
            tenant_id=str(TENANT),
            original_filename="a.md",
            storage_key="a",
            media_type="text/markdown",
            content_sha256="c" * 64,
            status="published",
            current_version_id=None,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    session.flush()
    session.add(
        DocumentVersionRow(
            id=str(version_id),
            document_id=str(doc_id),
            version_number=1,
            idempotency_key="v1",
            parsing_status="succeeded",
            chunking_status="succeeded",
            index_status="succeeded",
            parser_name="p",
            parser_version="1",
            chunking_strategy="rules",
            created_at=NOW,
            published_at=NOW,
        )
    )
    session.flush()
    doc = session.get(KnowledgeDocumentRow, str(doc_id))
    assert doc is not None
    doc.current_version_id = str(version_id)
    session.add(
        KnowledgeChunkRow(
            id=str(CHUNK),
            document_version_id=str(version_id),
            ordinal=0,
            heading_path_json=[],
            page_number=None,
            structural_location=None,
            text="trusted",
            token_count=1,
            content_sha256="d" * 64,
            sensitivity="internal",
            permission_tags_json=["security"],
            chunking_mode="rules",
            is_degraded=False,
        )
    )
    session.flush()
    ref = KnowledgeReference(CHUNK, CASE, "kb:chunk", NOW, "d" * 64)
    scope = AccessScope(
        TENANT,
        uuid4(),
        ("analyst",),
        (SensitivityLevel.INTERNAL,),
        ("security",),
        (base_id,),
    )
    private = AlertTriagePrivateContext(CASE, AgentRole.ALERT_TRIAGE, {}, (ref,), NOW)
    repo.upsert_private(
        session,
        tenant_id=TENANT,
        run_id=RUN,
        acting_role=AgentRole.ALERT_TRIAGE,
        context=private,
        expected_revision=None,
        knowledge_scope=scope,
    )
    denied_scopes = (
        None,
        AccessScope(
            OTHER, uuid4(), ("analyst",), (SensitivityLevel.INTERNAL,), ("security",), (base_id,)
        ),
        AccessScope(
            TENANT, uuid4(), ("analyst",), (SensitivityLevel.INTERNAL,), ("security",), (uuid4(),)
        ),
        AccessScope(
            TENANT, uuid4(), ("analyst",), (SensitivityLevel.INTERNAL,), ("other",), (base_id,)
        ),
    )
    for denied_scope in denied_scopes:
        with pytest.raises(InvalidTrustedReference):
            repo.upsert_private(
                session,
                tenant_id=TENANT,
                run_id=RUN,
                acting_role=AgentRole.ALERT_TRIAGE,
                context=private,
                expected_revision=0,
                knowledge_scope=denied_scope,
            )
    doc.status = "draft"
    with pytest.raises(InvalidTrustedReference):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=private,
            expected_revision=0,
            knowledge_scope=scope,
        )
    doc.status = "published"
    doc.current_version_id = None
    with pytest.raises(InvalidTrustedReference):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=private,
            expected_revision=0,
            knowledge_scope=scope,
        )
    doc.current_version_id = str(version_id)
    forged = replace(ref, integrity_sha256="e" * 64)
    with pytest.raises(InvalidTrustedReference):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=replace(private, references=(forged,)),
            expected_revision=0,
            knowledge_scope=scope,
        )
    denied = AccessScope(
        TENANT,
        uuid4(),
        ("analyst",),
        (SensitivityLevel.PUBLIC,),
        ("security",),
        (base_id,),
    )
    with pytest.raises(InvalidTrustedReference, match="not authorized"):
        repo.upsert_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            context=private,
            expected_revision=0,
            knowledge_scope=denied,
        )


def test_audit_failure_rolls_back_context(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("shieldchain.agents.repositories.append_incident_audit", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        SqlAlchemyAgentContextRepository().create_shared(
            session, tenant_id=TENANT, run_id=RUN, context=shared(), request_id="c"
        )
    assert session.scalar(select(func.count()).select_from(CaseContextRow)) == 0


def test_append_records_are_audited_and_append_audit_failure_rolls_back(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = SqlAlchemyAgentContextRepository()
    repo.create_shared(session, tenant_id=TENANT, run_id=RUN, context=shared(), request_id="c")
    fact = ConfirmedFact(uuid4(), "confirmed", True, (evidence_ref(),), 1.0, NOW)
    repo.append_fact(session, tenant_id=TENANT, run_id=RUN, fact=fact, request_id="fact")
    handoff = HandoffPacket(
        uuid4(),
        CASE,
        AgentRole.ALERT_TRIAGE,
        AgentRole.THREAT_INVESTIGATION,
        "investigate",
        (evidence_ref(),),
        0.9,
        (),
        ("continue",),
        NOW,
    )
    repo.append_handoff(
        session, tenant_id=TENANT, run_id=RUN, handoff=handoff, request_id="handoff"
    )
    output = AgentOutput(
        AgentRole.ALERT_TRIAGE, CASE, "triaged", (evidence_ref(),), (), (), ("continue",), NOW
    )
    repo.append_output(session, tenant_id=TENANT, run_id=RUN, output=output, request_id="output")
    assert session.scalar(select(func.count()).select_from(AuditEventRow)) == 4
    assert session.scalar(select(func.count()).select_from(ConfirmedCaseFactRow)) == 1
    assert session.scalar(select(func.count()).select_from(AgentHandoffRow)) == 1
    assert session.scalar(select(func.count()).select_from(AgentExecutionRow)) == 1

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("shieldchain.agents.repositories.append_incident_audit", fail)
    second = ConfirmedFact(uuid4(), "must roll back", True, (evidence_ref(),), 1.0, NOW)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        repo.append_fact(session, tenant_id=TENANT, run_id=RUN, fact=second, request_id="rollback")
    assert session.get(ConfirmedCaseFactRow, str(second.id)) is None


def test_append_only_repository_surface() -> None:
    public = {name for name in dir(SqlAlchemyAgentContextRepository) if not name.startswith("_")}
    assert not (
        {
            "update_fact",
            "delete_fact",
            "update_handoff",
            "delete_handoff",
            "update_output",
            "delete_output",
        }
        & public
    )


def test_same_incident_supports_multiple_runs_and_unknown_stored_kind_fails(
    session: Session,
) -> None:
    repo = SqlAlchemyAgentContextRepository()
    repo.create_shared(session, tenant_id=TENANT, run_id=RUN, context=shared(), request_id="one")
    second = uuid4()
    session.add(
        InvestigationRunRow(
            id=str(second),
            tenant_id=str(TENANT),
            incident_id=str(CASE),
            simulation_instance_id=str(UUID(int=101)),
            status="closed",
            mode="normal",
            created_at=NOW,
            updated_at=NOW,
            completed_at=NOW,
        )
    )
    session.flush()
    repo.create_shared(session, tenant_id=TENANT, run_id=second, context=shared(), request_id="two")
    assert repo.get_shared(session, tenant_id=TENANT, run_id=RUN) is not None
    assert repo.get_shared(session, tenant_id=TENANT, run_id=second) is not None

    private = AlertTriagePrivateContext(CASE, AgentRole.ALERT_TRIAGE, {}, (evidence_ref(),), NOW)
    repo.upsert_private(
        session,
        tenant_id=TENANT,
        run_id=RUN,
        acting_role=AgentRole.ALERT_TRIAGE,
        context=private,
        expected_revision=None,
    )
    row = session.scalar(
        select(AgentPrivateContextRow).where(AgentPrivateContextRow.run_id == str(RUN))
    )
    assert row is not None
    forged = [dict(row.references_json[0])]
    forged[0]["kind"] = "future_kind"
    row.references_json = forged
    session.flush()
    with pytest.raises(InvalidTrustedReference, match="kind"):
        repo.get_private(
            session,
            tenant_id=TENANT,
            run_id=RUN,
            acting_role=AgentRole.ALERT_TRIAGE,
            role=AgentRole.ALERT_TRIAGE,
        )
