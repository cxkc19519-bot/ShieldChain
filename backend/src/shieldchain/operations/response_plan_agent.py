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
    """Generate an advisory-only strict plan for a report-level operations run."""

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
        rule_ttl_seconds: int = 60,
    ) -> OperationsResponsePlanResult:
        actionable = self._actionable_target(target_ip)
        if not self._settings.deepseek_api_key.get_secret_value():
            return self._fallback(run_id, now, "model_unavailable", None, case_id=case_id)

        context = {
            "run_kind": "operations_report",
            "case_bound": case_id is not None,
            "execution_allowed": bool(case_id and target_evidence_id and actionable),
            "public_handoffs": [
                {
                    "role": str(item.get("role", ""))[:64],
                    "summary": str(item.get("summary", ""))[:600],
                }
                for item in public_handoffs[-4:]
            ],
            "observation_summaries": observation_summaries[:3000],
            "allowed_actions": (
                [
                    {
                        "tool": "block_ip",
                        "target_reference_id": str(target_evidence_id),
                        "arguments": {"rule_ttl_seconds": rule_ttl_seconds},
                        "expected_state": {"firewall_status": "blocked"},
                        "verification": {
                            "tool": "query_firewall_state",
                            "expected_state": {"firewall_status": "blocked"},
                        },
                    }
                ]
                if case_id and target_evidence_id and actionable
                else []
            ),
            "response_plan_schema": ResponsePlanCandidate.model_json_schema(),
        }
        try:
            response = await self._chat(
                "你是 ShieldChain 响应规划智能体。只输出一个符合 response_plan_schema 的"
                "完整 JSON 对象，"
                "不得输出 Markdown、解释文字或第二个对象。只能从 allowed_actions 复制允许的"
                "工具、证据引用、参数、期望状态和验证器；不得创造或修改目标。"
                "allowed_actions 为空时 assumptions 和 actions 必须为空。"
                "候选只是一份待人工审批计划，"
                "不能声称批准、执行、"
                "验证或完成处置。stop_conditions 至少一项。不得输出 tenant、principal、role、risk、"
                "approval、policy、幂等键、timeout、credential、URL、Shell、命令或代码。",
                json.dumps(context, ensure_ascii=False)[:12000],
            )
        except LlmError:
            return self._fallback(run_id, now, "model_unavailable", None, case_id=case_id)

        compiled = self._compiler.compile_json(
            response.content,
            self._context(run_id, now, response.model, case_id=case_id),
        )
        valid_advisory = (
            case_id is None
            and compiled.status is ResponsePlanStatus.COMPLETED_ADVISORY
            and not compiled.action_ids
        )
        valid_case_plan = (
            case_id is not None
            and actionable
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
                    "计划仍需人工接受及逐动作审批，尚未执行。"
                ),
            )
        reason_code = compiled.reason_code or "operations_report_action_forbidden"
        return self._fallback(run_id, now, reason_code, response.model, case_id=case_id)

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
    ) -> OperationsResponsePlanResult:
        candidate = {
            "action": "propose_response_plan",
            "public_summary": (
                "当前运营报告未绑定单一调查案件，因此不生成可执行处置动作；"
                "请人工核对报告线索并在案件级确认事实后重新规划。"
            ),
            "assumptions": [],
            "actions": [],
            "stop_conditions": ["缺少案件级确认事实或可验证目标"],
            "operator_notes": ["确定性安全降级；未批准、未执行、未验证任何处置动作"],
        }
        compiled = self._compiler.compile_json(
            json.dumps(candidate, ensure_ascii=False),
            self._context(run_id, now, model, case_id=case_id),
        )
        if compiled.status is not ResponsePlanStatus.COMPLETED_ADVISORY:
            raise RuntimeError("deterministic response plan fallback did not compile")
        return OperationsResponsePlanResult(
            reference=self._reference(compiled, "deterministic_fallback", reason_code),
            model=model,
            used_fallback=True,
            decision_reason=(
                f"严格候选未通过或模型不可用（{reason_code}），"
                "已生成零动作确定性建议；未创建可信工具调用。"
            ),
        )

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
