"""Automatic, bounded agent collaboration for a completed investigation analysis."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.model_planning import AutonomousPlan, DeepSeekAutonomousPlanner
from shieldchain.agents.persistence import (
    AgentExecutionRow,
    AgentHandoffRow,
    CaseContextRow,
    ConfirmedCaseFactRow,
)
from shieldchain.core.config import Settings
from shieldchain.incidents.domain import Assessment, Conclusion, Evidence
from shieldchain.incidents.persistence import IncidentRow, InvestigationRunRow
from shieldchain.incidents.repositories import append_incident_audit
from shieldchain.rag.api_service import KnowledgeApiService
from shieldchain.rag.schemas import RetrievalRequest


class InvestigationAgentRuntime:
    """Runs bounded specialist agents after deterministic evidence assessment.

    The runtime has no tool authority. Its only external capability is grounded
    RAG retrieval; enforcement remains in the investigation workflow and trusted
    tool gateway.
    """

    def __init__(
        self,
        sessions: sessionmaker[Session],
        knowledge: KnowledgeApiService,
        *,
        tenant_id: UUID,
        principal_id: UUID,
        settings: Settings | None = None,
    ) -> None:
        self._sessions = sessions
        self._knowledge = knowledge
        self._tenant_id = tenant_id
        self._principal_id = principal_id
        self._planner = DeepSeekAutonomousPlanner(settings)

    def run(
        self,
        run_id: UUID,
        *,
        evidence: tuple[Evidence, ...],
        assessment: Assessment,
        request_id: str,
        now: datetime,
    ) -> AutonomousPlan:
        with self._sessions.begin() as session:
            if session.get(CaseContextRow, str(run_id)) is not None:
                return
            run = session.get(InvestigationRunRow, str(run_id))
            if run is None or run.tenant_id != str(self._tenant_id):
                return
            incident = session.get(IncidentRow, run.incident_id)
            if incident is None:
                return

            evidence_refs = tuple(
                self._evidence_reference(item, UUID(incident.id)) for item in evidence
            )
            retrieval_summary, knowledge_refs = self._retrieve(incident, evidence)
            plan = self._planner.plan(
                assessment=assessment, evidence=evidence, grounded_knowledge=retrieval_summary
            )
            all_refs = [*evidence_refs, *knowledge_refs]
            is_threat = assessment.conclusion is Conclusion.CONFIRMED_THREAT
            actions = (
                ["建议通过可信工具网关阻断恶意远程地址"]
                if plan.allow_execution
                else ["建议转人工复核，不提交自动处置"]
            )
            role_rows = [
                (
                    "alert_triage",
                    f"已完成告警分诊，收集到 {len(evidence)} 条可信证据。",
                    evidence_refs,
                    actions,
                ),
                ("threat_investigation", assessment.explanation, evidence_refs, actions),
                ("knowledge_retrieval", retrieval_summary, knowledge_refs, actions),
                ("response_planning", plan.summary, all_refs, actions),
                (
                    "reporting",
                    "已汇总证据、研判和知识检索结果，生成可追溯报告摘要。",
                    all_refs,
                    actions,
                ),
            ]
            phase = "response_planning" if is_threat else "needs_review"
            context = CaseContextRow(
                id=str(run_id),
                run_id=str(run_id),
                tenant_id=str(self._tenant_id),
                revision=len(role_rows),
                phase=phase,
                user_goal="自动调查可疑安全事件并形成受控处置建议。",
                hypotheses_json=[],
                risks_json=(
                    [{"description": "检测到高风险威胁链", "severity": "high"}] if is_threat else []
                ),
                plan_json=["告警分诊", "威胁研判", "知识检索", "响应规划", "报告生成"],
                step_status_json={role: "completed" for role, *_rest in role_rows},
                disposition_status=(
                    "已形成受控处置建议" if is_threat else "证据不足，需要人工复核"
                ),
                budget_json={
                    "step_limit": 20,
                    "steps_used": len(role_rows),
                    "loop_limit": 5,
                    "loops_used": 0,
                    "time_limit_seconds": 300,
                    "time_used_seconds": 0,
                    "token_limit": 12000,
                    "tokens_used": 0,
                    "cost_limit_usd": 2.0,
                    "cost_used_usd": 0.0,
                    "tool_call_limit": 5,
                    "tool_calls_used": 0,
                },
                created_at=now,
                updated_at=now,
            )
            session.add(context)
            for index, item in enumerate(evidence[:5], start=1):
                session.add(
                    ConfirmedCaseFactRow(
                        id=str(uuid4()),
                        case_context_id=str(run_id),
                        tenant_id=str(self._tenant_id),
                        statement=f"可信证据 {index}：{item.summary}",
                        confirmed=True,
                        references_json=[self._evidence_reference(item, UUID(incident.id))],
                        confidence=item.confidence,
                        confirmed_at=now,
                        created_at=now,
                    )
                )
            for role, summary, refs, recommended_actions in role_rows:
                session.add(
                    AgentExecutionRow(
                        id=str(uuid4()),
                        run_id=str(run_id),
                        tenant_id=str(self._tenant_id),
                        role=role,
                        summary=summary[:4096],
                        references_json=list(refs),
                        hypotheses_json=[],
                        risks_json=[],
                        recommended_actions_json=recommended_actions,
                        termination_reason="completed",
                        created_at=now,
                    )
                )
            for (sender, summary, refs, actions_for_role), (receiver, *_rest) in zip(
                role_rows, role_rows[1:]
            ):
                session.add(
                    AgentHandoffRow(
                        id=str(uuid4()),
                        run_id=str(run_id),
                        tenant_id=str(self._tenant_id),
                        sender_role=sender,
                        receiver_role=receiver,
                        conclusion=summary[:4096],
                        references_json=list(refs),
                        confidence=0.7,
                        open_questions_json=[],
                        recommended_actions_json=actions_for_role,
                        created_at=now,
                    )
                )
            append_incident_audit(
                session,
                incident_id=UUID(incident.id),
                run_id=run_id,
                event_type="agent_orchestration_completed",
                request_id=request_id,
                occurred_at=now,
                payload={
                    "roles": [role for role, *_rest in role_rows],
                    "rag_auto_invoked": bool(knowledge_refs),
                    "model_planning": plan.model is not None,
                    "planner_model": plan.model,
                },
            )
            return plan

    def _retrieve(
        self, incident: IncidentRow, evidence: tuple[Evidence, ...]
    ) -> tuple[str, tuple[dict[str, object], ...]]:
        try:
            bases = tuple(self._knowledge.list_knowledge_bases(tenant_id=self._tenant_id))
            if not bases:
                return "未发现可用知识库；知识检索智能体已跳过 RAG 调用。", ()
            query = (
                f"{incident.threat_label} {incident.process_name} {incident.remote_ip} "
                + " ".join(item.summary for item in evidence[:3])
            )
            response = self._knowledge.retrieve(
                RetrievalRequest(
                    query=query[:4096], knowledge_base_ids=[base.id for base in bases], limit=3
                ),
                tenant_id=self._tenant_id,
                principal_id=self._principal_id,
            )
            references = tuple(
                {
                    "id": str(citation.chunk_id),
                    "kind": "knowledge",
                    "case_id": incident.id,
                    "source_id": f"knowledge:{citation.document_id}:{citation.document_version_id}",
                    "observed_at": citation.updated_at.astimezone(UTC).isoformat(),
                    "integrity_sha256": citation.integrity_sha256,
                }
                for citation in response.citations
            )
            return response.answer or "知识检索未返回可引用的答案。", references
        except Exception:
            return "知识检索智能体暂不可用；已保留确定性调查结果。", ()

    @staticmethod
    def _evidence_reference(item: Evidence, case_id: UUID) -> dict[str, object]:
        return {
            "id": str(item.id),
            "kind": "evidence",
            "case_id": str(case_id),
            "source_id": item.raw_reference,
            "observed_at": item.observed_at.astimezone(UTC).isoformat(),
            "integrity_sha256": item.integrity_sha256,
        }
