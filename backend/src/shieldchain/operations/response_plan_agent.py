from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, ip_network
from typing import Literal
from uuid import UUID

import httpx
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError
from shieldchain.response_planning.candidate import ResponsePlanCandidate
from shieldchain.response_planning.compiler import (
    CompiledResponsePlan,
    ResponsePlanCompileContext,
    ResponsePlanCompiler,
)
from shieldchain.response_planning.domain import ResponsePlanStatus
from shieldchain.response_planning.persistence import ResponsePlanRevisionRow

from .schemas import ResponsePlanReferenceView

_PROMPT_POLICY_VERSION = "operations-response-plan-v1"


@dataclass(frozen=True, slots=True)
class OperationsResponsePlanResult:
    reference: ResponsePlanReferenceView
    model: str | None
    used_fallback: bool
    decision_reason: str


class OperationsResponsePlanAgent:
    """Generate a strict advisory or case-bound response plan."""

    def __init__(
        self,
        settings: Settings,
        compiler: ResponsePlanCompiler,
        session_factory: sessionmaker[Session],
        *,
        tenant_id: UUID,
    ) -> None:
        self._settings = settings
        self._compiler = compiler
        self._session_factory = session_factory
        self._tenant_id = tenant_id

    async def generate(
        self,
        *,
        run_id: UUID,
        public_handoffs: list[dict[str, str]],
        observation_summaries: str,
        now: datetime,
        case_id: UUID | None = None,
        target_evidence_id: UUID | None = None,
        target_ip: str | None = None,
        target_endpoint_id: str | None = None,
        target_file_id: str | None = None,
        rule_ttl_seconds: int = 60,
    ) -> OperationsResponsePlanResult:
        actionable_ip = self._actionable_target(target_ip)
        actionable_endpoint = self._actionable_endpoint(target_endpoint_id)
        actionable_file = actionable_endpoint and self._actionable_file(target_file_id)
        allowed_actions = self._allowed_actions(
            target_evidence_id=target_evidence_id,
            actionable_ip=actionable_ip,
            actionable_endpoint=actionable_endpoint,
            actionable_file=actionable_file,
            target_file_id=target_file_id,
            rule_ttl_seconds=rule_ttl_seconds,
        )
        if not self._settings.deepseek_api_key.get_secret_value():
            return self._fallback(
                run_id,
                now,
                "model_unavailable",
                None,
                case_id=case_id,
                allowed_actions=allowed_actions,
            )

        context = {
            "run_kind": "operations_report",
            "case_bound": case_id is not None,
            "execution_allowed": bool(
                case_id and target_evidence_id and (actionable_ip or actionable_endpoint)
            ),
            "public_handoffs": [
                {
                    "role": str(item.get("role", ""))[:64],
                    "summary": str(item.get("summary", ""))[:600],
                }
                for item in public_handoffs[-4:]
            ],
            "observation_summaries": observation_summaries[:3000],
            "allowed_actions": allowed_actions,
            "response_plan_schema": ResponsePlanCandidate.model_json_schema(),
        }
        try:
            response = await self._chat(
                "你是 ShieldChain 响应规划智能体。只输出一个符合 response_plan_schema 的"
                "完整 JSON 对象，"
                "不得输出 Markdown、解释文字或第二个对象。只能从 allowed_actions 复制允许的"
                "完整动作对象；不得创造或修改任何字段。"
                "allowed_actions 为空时 assumptions 和 actions 必须为空。"
                "allowed_actions 非空时必须基于已确认案件证据选择至少一项改变状态的响应动作，"
                "并原样使用其验证器；不得只选择查询动作。"
                "候选只是未经策略引擎授权的计划，"
                "不能声称批准、执行、"
                "验证或完成处置。stop_conditions 至少一项。不得输出 tenant、principal、role、risk、"
                "approval、policy、幂等键、timeout、credential、URL、Shell、命令或代码。",
                json.dumps(context, ensure_ascii=False)[:12000],
            )
        except LlmError:
            return self._fallback(
                run_id,
                now,
                "model_unavailable",
                None,
                case_id=case_id,
                allowed_actions=allowed_actions,
            )

        try:
            parsed_candidate = ResponsePlanCandidate.model_validate_json(response.content)
        except ValueError:
            parsed_candidate = None
        if allowed_actions and parsed_candidate is not None and not parsed_candidate.actions:
            return self._fallback(
                run_id,
                now,
                "required_action_missing",
                response.model,
                case_id=case_id,
                allowed_actions=allowed_actions,
            )

        compiled = self._compiler.compile_json(
            response.content,
            self._context(run_id, now, response.model, case_id=case_id),
        )
        valid_advisory = (
            compiled.status is ResponsePlanStatus.COMPLETED_ADVISORY
            and not compiled.action_ids
            and (case_id is None or not (actionable_ip or actionable_endpoint))
        )
        valid_case_plan = (
            case_id is not None
            and (actionable_ip or actionable_endpoint)
            and compiled.status is ResponsePlanStatus.PROPOSED
            and bool(compiled.action_ids)
        )
        if compiled.reason_code is None and (valid_advisory or valid_case_plan):
            return OperationsResponsePlanResult(
                reference=self._reference(compiled, "model_compiled", None),
                model=response.model,
                used_fallback=False,
                decision_reason=(
                    "模型候选已通过严格 Schema、案件绑定和服务端编译；"
                    "计划尚未执行，后续由服务端响应策略决定自动闭环或人工审批。"
                ),
            )
        reason_code = compiled.reason_code or "operations_report_action_forbidden"
        return self._fallback(
            run_id,
            now,
            reason_code,
            response.model,
            case_id=case_id,
            allowed_actions=allowed_actions,
        )

    async def _chat(self, system: str, user: str):
        async with httpx.AsyncClient() as client:
            return await DeepSeekClient(self._settings, client).chat(
                ChatRequest(
                    messages=(
                        ChatMessage(role="system", content=system),
                        ChatMessage(role="user", content=user),
                    ),
                    temperature=0.0,
                    max_tokens=900,
                )
            )

    def _fallback(
        self,
        run_id: UUID,
        now: datetime,
        reason_code: str,
        model: str | None,
        *,
        case_id: UUID | None = None,
        allowed_actions: list[dict[str, object]] | None = None,
    ) -> OperationsResponsePlanResult:
        actions = allowed_actions or []
        candidate = {
            "action": "propose_response_plan",
            "public_summary": (
                "模型候选未通过严格校验，服务端已按案件证据和隔离回放白名单"
                "生成边界明确的处置计划。"
                if actions
                else "当前报告没有可安全处置的案件目标，因此不生成执行动作。"
            ),
            "assumptions": [],
            "actions": actions,
            "stop_conditions": (
                ["任一执行回执失败或验证状态与期望不一致时立即停止并重新规划"]
                if actions
                else ["缺少案件级确认事实或可验证目标"]
            ),
            "operator_notes": [
                "计划仅使用服务端白名单目标和参数；是否执行仍由服务端策略引擎决定"
            ],
        }
        compiled = self._compiler.compile_json(
            json.dumps(candidate, ensure_ascii=False),
            self._context(run_id, now, model, case_id=case_id),
        )
        expected_status = (
            ResponsePlanStatus.PROPOSED if actions else ResponsePlanStatus.COMPLETED_ADVISORY
        )
        if compiled.status is not expected_status:
            raise RuntimeError("deterministic response plan fallback did not compile")
        return OperationsResponsePlanResult(
            reference=self._reference(compiled, "deterministic_fallback", reason_code),
            model=model,
            used_fallback=True,
            decision_reason=(
                f"严格候选未通过或模型不可用（{reason_code}），"
                + (
                    "服务端已使用案件确认事实和白名单动作修复计划；计划尚未执行。"
                    if actions
                    else "已生成零动作确定性建议；未创建可信工具调用。"
                )
            ),
        )

    @staticmethod
    def _allowed_actions(
        *,
        target_evidence_id: UUID | None,
        actionable_ip: bool,
        actionable_endpoint: bool,
        actionable_file: bool,
        target_file_id: str | None,
        rule_ttl_seconds: int,
    ) -> list[dict[str, object]]:
        if target_evidence_id is None:
            return []
        reference = str(target_evidence_id)
        actions: list[dict[str, object]] = []
        if actionable_endpoint:
            actions.append(
                {
                    "client_action_id": "isolate_endpoint",
                    "tool": "isolate_endpoint",
                    "target_reference_id": reference,
                    "arguments": {
                        "reason_code": "containment_required",
                        "isolation_ttl_seconds": rule_ttl_seconds,
                    },
                    "expected_state": {"isolation_status": "isolated"},
                    "depends_on": [],
                    "public_reason": "隔离已确认告警对应的受控演示端点。",
                    "verification": {
                        "tool": "query_endpoint_state",
                        "expected_state": {"isolation_status": "isolated"},
                    },
                    "rollback_note": "验证失败或演示结束后恢复端点连接。",
                }
            )
        if actionable_file and target_file_id:
            actions.append(
                {
                    "client_action_id": "quarantine_file",
                    "tool": "quarantine_file",
                    "target_reference_id": reference,
                    "arguments": {
                        "file_id": target_file_id,
                        "reason_code": "confirmed_malicious",
                    },
                    "expected_state": {"file_status": "quarantined"},
                    "depends_on": (["isolate_endpoint"] if actionable_endpoint else []),
                    "public_reason": "隔离已确认告警证据指向的受控演示文件。",
                    "verification": {
                        "tool": "query_file_state",
                        "expected_state": {"file_status": "quarantined"},
                    },
                    "rollback_note": "误报或验证失败时恢复受控演示文件。",
                }
            )
        if actionable_ip:
            actions.append(
                {
                    "client_action_id": "block_source_ip",
                    "tool": "block_ip",
                    "target_reference_id": reference,
                    "arguments": {"rule_ttl_seconds": rule_ttl_seconds},
                    "expected_state": {"firewall_status": "blocked"},
                    "depends_on": [],
                    "public_reason": "临时封禁已确认告警中的受控演示源地址。",
                    "verification": {
                        "tool": "query_firewall_state",
                        "expected_state": {"firewall_status": "blocked"},
                    },
                    "rollback_note": "验证失败或规则到期后解除临时封禁。",
                }
            )
        return actions

    def _context(
        self, run_id: UUID, now: datetime, model: str | None, *, case_id: UUID | None = None
    ) -> ResponsePlanCompileContext:
        return ResponsePlanCompileContext(
            tenant_id=self._tenant_id,
            run_id=run_id,
            case_id=case_id,
            model_id=model,
            prompt_policy_version=_PROMPT_POLICY_VERSION,
            now=now,
        )

    def _actionable_target(self, value: str | None) -> bool:
        if not value:
            return False
        try:
            address = IPv4Address(value)
            networks = tuple(
                ip_network(item.strip(), strict=False)
                for item in self._settings.response_firewall_allowed_cidrs.split(",")
                if item.strip()
            )
        except ValueError:
            return False
        return any(address in network for network in networks)

    def _actionable_endpoint(self, value: str | None) -> bool:
        if not value:
            return False
        allowed = {
            item.strip()
            for item in self._settings.response_wazuh_allowed_agent_ids.split(",")
            if item.strip()
        }
        return value.strip() in allowed

    def _actionable_file(self, value: str | None) -> bool:
        if not value:
            return False
        allowed = {
            item.strip()
            for item in self._settings.response_allowed_file_ids.split(",")
            if item.strip()
        }
        return value.strip() in allowed

    def _reference(
        self,
        compiled: CompiledResponsePlan,
        generation_status: Literal["model_compiled", "deterministic_fallback"],
        fallback_reason_code: str | None,
    ) -> ResponsePlanReferenceView:
        with self._session_factory() as session:
            revision = session.get(ResponsePlanRevisionRow, str(compiled.revision_id))
            if revision is None or revision.tenant_id != str(self._tenant_id):
                raise RuntimeError("compiled response plan revision is missing")
            public_summary = revision.public_summary
        return ResponsePlanReferenceView(
            plan_id=compiled.plan_id,
            revision_id=compiled.revision_id,
            revision=compiled.revision,
            status=compiled.status.value,
            public_summary=public_summary,
            action_count=len(compiled.action_ids),
            generation_status=generation_status,
            fallback_reason_code=fallback_reason_code,
            execution_status="not_executed",
        )
