from __future__ import annotations

import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from time import perf_counter
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from .agent import VulnerabilityModelUnavailable, VulnerabilityTriageAgent
from .persistence import VulnerabilityFindingRow, VulnerabilityWorkflowEventRow
from .schemas import (
    VulnerabilityChangeRequest,
    VulnerabilityDecisionRequest,
    VulnerabilityDemoRunView,
    VulnerabilityDemoToolCallView,
    VulnerabilityFindingIngestRequest,
    VulnerabilityFindingIngestResponse,
    VulnerabilityFindingListResponse,
    VulnerabilityFindingView,
    VulnerabilityImplementationRequest,
    VulnerabilityMetricsView,
    VulnerabilityMutationView,
    VulnerabilityTriageRequest,
    VulnerabilityVerificationRequest,
    VulnerabilityWorkflowEventView,
)


class VulnerabilityWorkflowError(RuntimeError):
    pass


class VulnerabilityNotFound(VulnerabilityWorkflowError):
    pass


def _utc(value: datetime) -> datetime:
    """Restore UTC awareness lost by SQLite datetime round-trips."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class _DemoFinding:
    scenario: str
    asset_id: str
    asset_name: str
    cve_id: str
    severity: str
    cvss_score: float
    package_name: str
    installed_version: str | None
    fixed_version: str | None
    remediation_tool: str
    verification_tool: str
    action_summary: str
    first_retest_fails: bool = False
    resolution: str = "remediate"


_DEMO_FINDINGS = (
    _DemoFinding(
        "component_upgrade",
        "demo-web-01",
        "演示 Web 服务器",
        "CVE-2026-41001",
        "critical",
        9.8,
        "demo-web-runtime",
        "4.2.0",
        "4.2.1",
        "demo.patch.apply@1",
        "demo.scanner.retest@1",
        "升级存在缺陷的 Web 运行组件。",
    ),
    _DemoFinding(
        "configuration_hardening",
        "demo-api-02",
        "演示 API 网关",
        "CVE-2026-41002",
        "high",
        8.6,
        "demo-api-gateway",
        "3.7.5",
        None,
        "demo.config.harden@1",
        "demo.config.audit@1",
        "关闭危险配置并应用安全基线。",
    ),
    _DemoFinding(
        "container_image_replacement",
        "demo-worker-03",
        "演示任务节点",
        "CVE-2026-41003",
        "high",
        8.1,
        "demo-worker-service",
        "2.9.1",
        "2.9.2",
        "demo.image.replace@1",
        "demo.image.scan@1",
        "替换存在漏洞的容器镜像并重新部署。",
    ),
    _DemoFinding(
        "service_exposure_reduction",
        "demo-edge-04",
        "演示边缘服务",
        "CVE-2026-41004",
        "high",
        7.9,
        "demo-admin-service",
        None,
        None,
        "demo.network.restrict@1",
        "demo.scanner.port_retest@1",
        "收敛管理服务暴露范围并关闭非必要端口。",
    ),
    _DemoFinding(
        "retest_failure_replan",
        "demo-file-05",
        "演示文件处理服务",
        "CVE-2026-41005",
        "critical",
        9.1,
        "demo-file-parser",
        "6.0.0",
        "6.0.1",
        "demo.patch.apply@1",
        "demo.scanner.retest@1",
        "升级文件解析组件；若服务仍加载旧版本，则根据复测反馈重新规划。",
        True,
    ),
    _DemoFinding(
        "compensating_control",
        "demo-business-06",
        "演示关键业务中间件",
        "CVE-2026-41006",
        "high",
        8.4,
        "demo-business-middleware",
        "8.3.0",
        None,
        "demo.control.apply@1",
        "demo.control.verify@1",
        "在暂无补丁时启用隔离规则和攻击面补偿控制。",
    ),
    _DemoFinding(
        "scanner_false_positive",
        "demo-data-07",
        "演示数据服务",
        "CVE-2026-41007",
        "medium",
        6.4,
        "demo-data-library",
        "5.4.0",
        "5.4.1",
        "demo.version.verify@1",
        "demo.version.verify@1",
        "核对制品清单和运行时加载版本，排除扫描器误报。",
        False,
        "not_affected",
    ),
)

class VulnerabilityWorkflowService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        agent: VulnerabilityTriageAgent,
        *,
        scanner_token: str,
        tenant_id: UUID,
        principal_id: UUID,
    ) -> None:
        self._sessions = sessions
        self._agent = agent
        self._scanner_token = scanner_token
        self._tenant_id = str(tenant_id)
        self._principal_id = str(principal_id)

    def scanner_authorized(self, token: str | None) -> bool:
        return bool(
            self._scanner_token and token and secrets.compare_digest(self._scanner_token, token)
        )

    async def run_demo_closed_loop(self) -> VulnerabilityDemoRunView:
        """Run one isolated, stateful vulnerability workflow through explicit demo tools."""
        started = perf_counter()
        demo_id = uuid4().hex
        base_sample = secrets.choice(_DEMO_FINDINGS)
        cve_number = 10_000_000 + (int(demo_id[:8], 16) % 90_000_000)
        sample = replace(
            base_sample,
            asset_id=f"{base_sample.asset_id}-{demo_id[:8]}",
            asset_name=f"{base_sample.asset_name} #{demo_id[:6].upper()}",
            cve_id=f"CVE-2026-{cve_number:08d}",
        )
        observed_at = datetime.now(UTC)
        ingested = self.ingest(
            VulnerabilityFindingIngestRequest(
                external_id=f"shieldchain-demo-{demo_id}",
                scanner="ShieldChain 隔离演示扫描器",
                asset_id=sample.asset_id,
                asset_name=sample.asset_name,
                cve_id=sample.cve_id,
                severity=sample.severity,
                cvss_score=sample.cvss_score,
                package_name=sample.package_name,
                installed_version=sample.installed_version,
                fixed_version=sample.fixed_version,
                observed_at=observed_at,
                evidence={
                    "source_kind": "isolated_vulnerability_demo",
                    "isolated_asset": True,
                    "version_match": (
                        "runtime_component_mismatch"
                        if sample.resolution == "not_affected"
                        else "confirmed"
                    ),
                    "scanner_signature_match": sample.resolution != "not_affected",
                    "scanner_task": f"demo-scan-{demo_id[:12]}",
                    "scenario": sample.scenario,
                },
            )
        )
        finding_id = ingested.finding.id
        triaged = await self.triage(
            finding_id,
            VulnerabilityTriageRequest(
                business_context=(
                    f"隔离比赛演示资产；场景为 {sample.scenario}；必须依据当前证据独立研判。"
                )
            ),
        )
        plan_summary = str(triaged.event.details.get("remediation") or triaged.event.summary)
        action_tools = {
            sample.remediation_tool: sample.action_summary,
            "demo.network.restrict@1": "限制漏洞资产的入站访问面并保留业务必要流量。",
            "demo.service.restart@1": "重启服务以重新加载已经更新的组件或安全配置。",
            "demo.version.verify@1": "核对制品清单、运行时组件及扫描器签名是否一致。",
        }
        verification_tools = {
            sample.verification_tool: "针对当前组件和漏洞特征执行复测并返回是否仍命中。",
            "demo.scanner.retest@1": "使用隔离扫描器重新检测漏洞特征。",
            "demo.config.audit@1": "复核配置基线与服务暴露状态。",
        }
        try:
            with self._sessions() as session:
                decision_finding = self._get(session, finding_id)
                session.expunge(decision_finding)
            decision = await self._agent.decide_next_action(
                decision_finding,
                triage_summary=triaged.event.summary,
                action_tools=action_tools,
                verification_tools=verification_tools,
            )
        except VulnerabilityModelUnavailable as error:
            raise VulnerabilityWorkflowError(str(error)) from error
        self._transition(
            finding_id,
            allowed={"triaged"},
            target=(
                "triaged" if decision.action == "verify_not_affected" else "remediation_approved"
            ),
            event_type="demo_policy_authorized",
            reason_code="agent_plan_within_isolated_policy",
            summary=(
                f"处置智能体选择 {decision.tool_name}；隔离权限与工具目录校验通过。"
                f"决策依据：{decision.rationale}"
            ),
            details={
                "mode": "isolated_simulation",
                "human_interventions": 0,
                "plan_summary": plan_summary,
                "scenario": sample.scenario,
                "agent_model": decision.model,
                "agent_action": decision.action,
                "selected_tool": decision.tool_name,
                "selected_verification_tool": decision.verification_tool,
                "decision_rationale": decision.rationale,
                "success_criteria": decision.success_criteria,
                "policy_checks": [
                    "isolated_asset",
                    "tool_in_allowed_catalog",
                    "verification_tool_in_allowed_catalog",
                ],
            },
            actor_type="system",
            actor_id="vulnerability_demo_policy",
        )
        tool_calls: list[VulnerabilityDemoToolCallView] = []
        if decision.action == "verify_not_affected":
            tool_calls.append(
                self._close_demo_not_affected(
                    finding_id, decision.tool_name, decision.rationale
                )
            )
        else:
            tool_calls.append(self._run_demo_remediation(finding_id, decision.tool_name))
            first_passed = not sample.first_retest_fails
            tool_calls.append(
                self._run_demo_verification(
                    finding_id,
                    decision.verification_tool,
                    passed=first_passed,
                    attempt=1,
                )
            )
            if not first_passed:
                feedback = (
                    f"工具 {decision.verification_tool} 第 1 次复测仍命中漏洞特征；"
                    "已执行的处置未满足成功标准，请根据反馈重新选择下一动作。"
                )
                try:
                    with self._sessions() as session:
                        replan_finding = self._get(session, finding_id)
                        session.expunge(replan_finding)
                    replan = await self._agent.decide_next_action(
                        replan_finding,
                        triage_summary=triaged.event.summary,
                        action_tools=action_tools,
                        verification_tools=verification_tools,
                        feedback=feedback,
                    )
                except VulnerabilityModelUnavailable as error:
                    raise VulnerabilityWorkflowError(str(error)) from error
                self._transition(
                    finding_id,
                    allowed={"triaged"},
                    target=(
                        "triaged"
                        if replan.action == "verify_not_affected"
                        else "remediation_approved"
                    ),
                    event_type="demo_replan_authorized",
                    reason_code="agent_replan_within_isolated_policy",
                    summary=(
                        f"处置智能体观察到复测失败后重新选择 {replan.tool_name}。"
                        f"决策依据：{replan.rationale}"
                    ),
                    details={
                        "scenario": sample.scenario,
                        "feedback": feedback,
                        "agent_model": replan.model,
                        "agent_action": replan.action,
                        "new_tool": replan.tool_name,
                        "selected_verification_tool": replan.verification_tool,
                        "decision_rationale": replan.rationale,
                        "success_criteria": replan.success_criteria,
                        "human_interventions": 0,
                    },
                    actor_type="agent",
                    actor_id="vulnerability_response_agent",
                )
                if replan.action == "verify_not_affected":
                    tool_calls.append(
                        self._close_demo_not_affected(
                            finding_id, replan.tool_name, replan.rationale
                        )
                    )
                else:
                    tool_calls.append(
                        self._run_demo_remediation(finding_id, replan.tool_name)
                    )
                    tool_calls.append(
                        self._run_demo_verification(
                            finding_id,
                            replan.verification_tool,
                            passed=True,
                            attempt=2,
                        )
                    )
        final = self.get(finding_id)
        return VulnerabilityDemoRunView(
            finding=final,
            scenario=sample.scenario,
            total_duration_ms=max(1, int((perf_counter() - started) * 1000)),
            tool_calls=tool_calls,
        )

    def ingest(
        self, request: VulnerabilityFindingIngestRequest
    ) -> VulnerabilityFindingIngestResponse:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            existing = session.scalar(
                select(VulnerabilityFindingRow).where(
                    VulnerabilityFindingRow.tenant_id == self._tenant_id,
                    VulnerabilityFindingRow.scanner == request.scanner,
                    VulnerabilityFindingRow.external_id == request.external_id,
                )
            )
            if existing is not None:
                if _utc(request.observed_at) > _utc(existing.last_seen_at):
                    existing.last_seen_at = request.observed_at
                    existing.updated_at = now
                return VulnerabilityFindingIngestResponse(
                    created=False, finding=self._view(session, existing)
                )
            row = VulnerabilityFindingRow(
                id=str(uuid4()),
                tenant_id=self._tenant_id,
                status="new",
                scanner=request.scanner,
                external_id=request.external_id,
                asset_id=request.asset_id,
                asset_name=request.asset_name,
                cve_id=request.cve_id,
                severity=request.severity,
                cvss_score=request.cvss_score,
                package_name=request.package_name,
                installed_version=request.installed_version,
                fixed_version=request.fixed_version,
                evidence_json=request.evidence,
                first_seen_at=request.observed_at,
                last_seen_at=request.observed_at,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            self._event(
                session,
                row,
                event_type="finding_ingested",
                actor_type="scanner",
                actor_id=request.scanner,
                from_status=None,
                to_status="new",
                reason_code="scanner_observation",
                summary="扫描器提交新的漏洞发现，尚未完成人工影响确认。",
                details={"evidence": request.evidence},
                now=now,
            )
            return VulnerabilityFindingIngestResponse(
                created=True, finding=self._view(session, row)
            )

    def list(self) -> VulnerabilityFindingListResponse:
        with self._sessions() as session:
            rows = session.scalars(
                select(VulnerabilityFindingRow)
                .where(VulnerabilityFindingRow.tenant_id == self._tenant_id)
                .order_by(VulnerabilityFindingRow.updated_at.desc())
                .limit(200)
            ).all()
            return VulnerabilityFindingListResponse(
                items=[self._view(session, row) for row in rows]
            )

    def get(self, finding_id: UUID) -> VulnerabilityFindingView:
        with self._sessions() as session:
            return self._view(session, self._get(session, finding_id))

    def delete(self, finding_id: UUID) -> None:
        """Delete one finding and its complete workflow history within the tenant."""

        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            session.execute(
                delete(VulnerabilityWorkflowEventRow).where(
                    VulnerabilityWorkflowEventRow.tenant_id == self._tenant_id,
                    VulnerabilityWorkflowEventRow.finding_id == row.id,
                )
            )
            session.delete(row)

    async def triage(
        self, finding_id: UUID, request: VulnerabilityTriageRequest
    ) -> VulnerabilityMutationView:
        with self._sessions() as session:
            finding = self._get(session, finding_id)
            if finding.status not in {"new", "triaged"}:
                raise VulnerabilityWorkflowError("finding cannot be triaged in its current status")
            try:
                result = await self._agent.analyze(finding, request.business_context)
            except VulnerabilityModelUnavailable as error:
                raise VulnerabilityWorkflowError(str(error)) from error
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            if row.status not in {"new", "triaged"}:
                raise VulnerabilityWorkflowError("finding changed while agent was analyzing it")
            previous = row.status
            row.status = "triaged"
            row.updated_at = now
            event = self._event(
                session,
                row,
                event_type="agent_triage_completed",
                actor_type="agent",
                actor_id="vulnerability_triage",
                from_status=previous,
                to_status="triaged",
                reason_code="model_assessment"
                if result.status == "completed"
                else "conservative_fallback",
                summary=result.summary,
                details={
                    "agent_name": "漏洞研判智能体",
                    "agent_status": result.status,
                    "model": result.model,
                    "priority": result.priority,
                    "affected_assessment": result.affected_assessment,
                    "remediation": result.remediation,
                    "verification": result.verification,
                    "evidence_gaps": result.evidence_gaps,
                    "knowledge_citations": result.knowledge_citations,
                },
                now=now,
            )
            return VulnerabilityMutationView(
                finding=self._view(session, row), event=self._event_view(event)
            )

    def decide(
        self, finding_id: UUID, request: VulnerabilityDecisionRequest
    ) -> VulnerabilityMutationView:
        now = datetime.now(UTC)
        if request.risk_expires_at is not None:
            expires = _utc(request.risk_expires_at)
            if expires <= now or expires > now + timedelta(days=365):
                raise VulnerabilityWorkflowError("risk acceptance expiry must be within 365 days")
        target, event_type = {
            "approve_remediation": ("remediation_approved", "remediation_approved"),
            "accept_risk": ("accepted_risk", "risk_accepted"),
            "mark_not_affected": ("closed", "finding_not_affected"),
        }[request.outcome]
        return self._transition(
            finding_id,
            allowed={"triaged"},
            target=target,
            event_type=event_type,
            reason_code=request.reason_code,
            summary=request.rationale,
            details={
                "risk_expires_at": request.risk_expires_at.isoformat()
                if request.risk_expires_at
                else None
            },
        )

    def start_change(
        self, finding_id: UUID, request: VulnerabilityChangeRequest
    ) -> VulnerabilityMutationView:
        return self._transition(
            finding_id,
            allowed={"remediation_approved"},
            target="remediation_in_progress",
            event_type="remediation_started",
            reason_code="approved_change",
            summary=request.plan_summary,
            details={
                "change_ticket": request.change_ticket,
                "implementer": request.implementer,
                "planned_at": request.planned_at.isoformat(),
            },
        )

    def complete_change(
        self, finding_id: UUID, request: VulnerabilityImplementationRequest
    ) -> VulnerabilityMutationView:
        return self._transition(
            finding_id,
            allowed={"remediation_in_progress"},
            target="verification_pending",
            event_type="remediation_completed",
            reason_code="implementation_recorded",
            summary=request.implementation_summary,
            details={
                "change_ticket": request.change_ticket,
                "evidence_references": request.evidence_references,
            },
        )

    def verify(
        self, finding_id: UUID, request: VulnerabilityVerificationRequest
    ) -> VulnerabilityMutationView:
        passed = request.result == "passed"
        return self._transition(
            finding_id,
            allowed={"verification_pending"},
            target="closed" if passed else "triaged",
            event_type="verification_passed" if passed else "verification_failed",
            reason_code="scanner_retest_passed" if passed else "scanner_retest_failed",
            summary=request.summary,
            details={
                "scanner": request.scanner,
                "observed_version": request.observed_version,
                "evidence_references": request.evidence_references,
            },
        )

    def metrics(self) -> VulnerabilityMetricsView:
        with self._sessions() as session:
            rows = session.execute(
                select(
                    VulnerabilityFindingRow.status, VulnerabilityFindingRow.severity, func.count()
                )
                .where(VulnerabilityFindingRow.tenant_id == self._tenant_id)
                .group_by(VulnerabilityFindingRow.status, VulnerabilityFindingRow.severity)
            ).all()

        def count(statuses: set[str]) -> int:
            return sum(number for status, _severity, number in rows if status in statuses)

        open_statuses = {
            "new",
            "triaged",
            "remediation_approved",
            "remediation_in_progress",
            "verification_pending",
        }
        return VulnerabilityMetricsView(
            total=sum(number for _status, _severity, number in rows),
            open=count(open_statuses),
            critical_open=sum(
                number
                for status, severity, number in rows
                if status in open_statuses and severity == "critical"
            ),
            awaiting_approval=count({"triaged"}),
            verification_pending=count({"verification_pending"}),
            closed=count({"closed"}),
            accepted_risk=count({"accepted_risk"}),
        )

    def _transition(
        self,
        finding_id: UUID,
        *,
        allowed: set[str],
        target: str,
        event_type: str,
        reason_code: str,
        summary: str,
        details: dict[str, object],
        actor_type: str = "human",
        actor_id: str | None = None,
    ) -> VulnerabilityMutationView:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            if row.status not in allowed:
                raise VulnerabilityWorkflowError(f"transition from {row.status} is not allowed")
            previous = row.status
            row.status = target
            row.updated_at = now
            event = self._event(
                session,
                row,
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id or self._principal_id,
                from_status=previous,
                to_status=target,
                reason_code=reason_code,
                summary=summary,
                details=details,
                now=now,
            )
            return VulnerabilityMutationView(
                finding=self._view(session, row), event=self._event_view(event)
            )

    def _run_demo_remediation(
        self, finding_id: UUID, tool_name: str
    ) -> VulnerabilityDemoToolCallView:
        call_id = uuid4()
        started = perf_counter()
        self._transition(
            finding_id,
            allowed={"remediation_approved"},
            target="remediation_in_progress",
            event_type="demo_remediation_started",
            reason_code="trusted_demo_tool_dispatched",
            summary=f"响应智能体调用隔离模拟工具 {tool_name}。",
            details={
                "tool_name": tool_name,
                "tool_call_id": str(call_id),
                "tool_status": "running",
                "simulation": True,
            },
            actor_type="agent",
            actor_id="vulnerability_response_agent",
        )
        duration_ms = max(1, int((perf_counter() - started) * 1000))
        summary = self._apply_demo_fix(finding_id, call_id, duration_ms, tool_name)
        return VulnerabilityDemoToolCallView(
            call_id=call_id,
            tool_name=tool_name,
            status="succeeded",
            duration_ms=duration_ms,
            summary=summary,
        )

    def _apply_demo_fix(
        self, finding_id: UUID, call_id: UUID, duration_ms: int, tool_name: str
    ) -> str:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            if row.status != "remediation_in_progress":
                raise VulnerabilityWorkflowError("demo remediation preconditions are not satisfied")
            previous_version = row.installed_version
            if row.fixed_version:
                row.installed_version = row.fixed_version
            evidence = dict(row.evidence_json)
            evidence["demo_remediation_applied"] = True
            evidence["last_demo_tool"] = tool_name
            row.evidence_json = evidence
            row.status = "verification_pending"
            row.updated_at = now
            receipt = call_id.hex[:8].upper()
            summary = (
                f"执行回执 {receipt}：隔离模拟工具 {tool_name} 执行成功；"
                f"组件版本从 {previous_version} "
                f"变更为 {row.installed_version}。"
                if row.fixed_version
                else f"执行回执 {receipt}：隔离模拟工具 {tool_name} 已成功应用场景要求的安全控制。"
            )
            self._event(
                session,
                row,
                event_type="demo_remediation_succeeded",
                actor_type="system",
                actor_id="vulnerability_response_agent",
                from_status="remediation_in_progress",
                to_status="verification_pending",
                reason_code="simulated_patch_applied",
                summary=summary,
                details={
                    "tool_name": tool_name,
                    "tool_call_id": str(call_id),
                    "tool_status": "succeeded",
                    "duration_ms": duration_ms,
                    "simulation": True,
                    "previous_version": previous_version,
                    "observed_version": row.installed_version,
                },
                now=now,
            )
            return summary

    def _run_demo_verification(
        self,
        finding_id: UUID,
        tool_name: str,
        *,
        passed: bool,
        attempt: int,
    ) -> VulnerabilityDemoToolCallView:
        call_id = uuid4()
        started = perf_counter()
        duration_ms = max(1, int((perf_counter() - started) * 1000))
        summary = self._verify_demo_fix(
            finding_id,
            call_id,
            duration_ms,
            tool_name,
            passed=passed,
            attempt=attempt,
        )
        return VulnerabilityDemoToolCallView(
            call_id=call_id,
            tool_name=tool_name,
            status="succeeded" if passed else "failed",
            duration_ms=duration_ms,
            summary=summary,
        )

    def _verify_demo_fix(
        self,
        finding_id: UUID,
        call_id: UUID,
        duration_ms: int,
        tool_name: str,
        *,
        passed: bool,
        attempt: int,
    ) -> str:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            row = self._get(session, finding_id)
            if row.status != "verification_pending":
                raise VulnerabilityWorkflowError(
                    "demo verification preconditions are not satisfied"
                )
            applied = bool(row.evidence_json.get("demo_remediation_applied"))
            if passed and not applied:
                raise VulnerabilityWorkflowError("demo scanner retest lacks remediation evidence")
            row.status = "closed" if passed else "triaged"
            row.updated_at = now
            receipt = call_id.hex[:8].upper()
            summary = (
                f"执行回执 {receipt}：隔离模拟工具 {tool_name} "
                f"第 {attempt} 次复测通过，漏洞闭环完成。"
                if passed
                else (
                    f"执行回执 {receipt}：隔离模拟工具 {tool_name} 第 {attempt} 次复测仍发现风险，"
                    "已将反馈交给智能体重新规划。"
                )
            )
            self._event(
                session,
                row,
                event_type="demo_verification_passed" if passed else "demo_verification_failed",
                actor_type="system",
                actor_id="vulnerability_verification_agent",
                from_status="verification_pending",
                to_status="closed" if passed else "triaged",
                reason_code=(
                    "simulated_scanner_retest_passed"
                    if passed
                    else "simulated_scanner_retest_failed"
                ),
                summary=summary,
                details={
                    "tool_name": tool_name,
                    "tool_call_id": str(call_id),
                    "tool_status": "succeeded" if passed else "failed",
                    "duration_ms": duration_ms,
                    "simulation": True,
                    "observed_version": row.installed_version,
                    "finding_present": not passed,
                    "attempt": attempt,
                    "human_interventions": 0,
                },
                now=now,
            )
            return summary

    def _close_demo_not_affected(
        self, finding_id: UUID, tool_name: str, rationale: str
    ) -> VulnerabilityDemoToolCallView:
        call_id = uuid4()
        started = perf_counter()
        duration_ms = max(1, int((perf_counter() - started) * 1000))
        summary = (
            f"执行回执 {call_id.hex[:8].upper()}：制品清单与运行时加载证据均表明扫描器签名"
            f"未命中实际组件，智能体确认该隔离样本不受影响。决策依据：{rationale}"
        )
        self._transition(
            finding_id,
            allowed={"triaged"},
            target="closed",
            event_type="demo_not_affected_verified",
            reason_code="simulated_evidence_confirmed_not_affected",
            summary=summary,
            details={
                "tool_name": tool_name,
                "tool_call_id": str(call_id),
                "tool_status": "succeeded",
                "duration_ms": duration_ms,
                "simulation": True,
                "finding_present": False,
                "human_interventions": 0,
            },
            actor_type="agent",
            actor_id="vulnerability_verification_agent",
        )
        return VulnerabilityDemoToolCallView(
            call_id=call_id,
            tool_name=tool_name,
            status="succeeded",
            duration_ms=duration_ms,
            summary=summary,
        )

    def _get(self, session: Session, finding_id: UUID) -> VulnerabilityFindingRow:
        row = session.scalar(
            select(VulnerabilityFindingRow).where(
                VulnerabilityFindingRow.id == str(finding_id),
                VulnerabilityFindingRow.tenant_id == self._tenant_id,
            )
        )
        if row is None:
            raise VulnerabilityNotFound("vulnerability finding not found")
        return row

    def _view(self, session: Session, row: VulnerabilityFindingRow) -> VulnerabilityFindingView:
        events = list(
            session.scalars(
                select(VulnerabilityWorkflowEventRow)
                .where(
                    VulnerabilityWorkflowEventRow.tenant_id == self._tenant_id,
                    VulnerabilityWorkflowEventRow.finding_id == row.id,
                )
                .order_by(
                    VulnerabilityWorkflowEventRow.created_at, VulnerabilityWorkflowEventRow.id
                )
            )
        )
        views = [self._event_view(item) for item in events]
        latest = next(
            (item for item in reversed(views) if item.event_type == "agent_triage_completed"), None
        )
        return VulnerabilityFindingView(
            id=UUID(row.id),
            scanner=row.scanner,
            external_id=row.external_id,
            asset_id=row.asset_id,
            asset_name=row.asset_name,
            cve_id=row.cve_id,
            severity=row.severity,
            cvss_score=row.cvss_score,
            package_name=row.package_name,
            installed_version=row.installed_version,
            fixed_version=row.fixed_version,
            status=row.status,
            first_seen_at=_utc(row.first_seen_at),
            last_seen_at=_utc(row.last_seen_at),
            created_at=_utc(row.created_at),
            updated_at=_utc(row.updated_at),
            latest_triage=latest,
            events=views,
        )

    @staticmethod
    def _event(
        session: Session,
        row: VulnerabilityFindingRow,
        *,
        event_type: str,
        actor_type: str,
        actor_id: str,
        from_status: str | None,
        to_status: str,
        reason_code: str,
        summary: str,
        details: dict[str, object],
        now: datetime,
    ) -> VulnerabilityWorkflowEventRow:
        event = VulnerabilityWorkflowEventRow(
            id=str(uuid4()),
            finding_id=row.id,
            tenant_id=row.tenant_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            from_status=from_status,
            to_status=to_status,
            reason_code=reason_code,
            summary=summary,
            details_json=details,
            created_at=now,
        )
        session.add(event)
        session.flush()
        return event

    @staticmethod
    def _event_view(row: VulnerabilityWorkflowEventRow) -> VulnerabilityWorkflowEventView:
        return VulnerabilityWorkflowEventView(
            id=UUID(row.id),
            event_type=row.event_type,
            actor_type=row.actor_type,
            from_status=row.from_status,
            to_status=row.to_status,
            reason_code=row.reason_code,
            summary=row.summary,
            details=row.details_json,
            created_at=_utc(row.created_at),
        )
