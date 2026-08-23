from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
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
    ) -> OperationsResponsePlanResult:
        if not self._settings.deepseek_api_key.get_secret_value():
            return self._fallback(run_id, now, "model_unavailable", None)

        context = {
            "run_kind": "operations_report",
            "case_bound": False,
            "execution_allowed": False,
            "public_handoffs": [
                {
                    "role": str(item.get("role", ""))[:64],
                    "summary": str(item.get("summary", ""))[:600],
                }
                for item in public_handoffs[-4:]
            ],
            "observation_summaries": observation_summaries[:3000],
            "allowed_actions": [],
            "response_plan_schema": ResponsePlanCandidate.model_json_schema(),
        }
        try:
            response = await self._chat(
                "你是 ShieldChain 响应规划智能体。只输出一个符合 response_plan_schema 的"
                "完整 JSON 对象，"
                "不得输出 Markdown、解释文字或第二个对象。当前是未绑定单一案件的运营报告运行，"
                "因此 assumptions 和 actions 必须为空；只能形成待人工复核的建议，"
                "不能声称批准、执行、"
                "验证或完成处置。stop_conditions 至少一项。不得输出 tenant、principal、role、risk、"
                "approval、policy、幂等键、timeout、credential、URL、Shell、命令或代码。",
                json.dumps(context, ensure_ascii=False)[:12000],
            )
        except LlmError:
            return self._fallback(run_id, now, "model_unavailable", None)

        compiled = self._compiler.compile_json(
            response.content,
            self._context(run_id, now, response.model),
        )
        if (
            compiled.status is ResponsePlanStatus.COMPLETED_ADVISORY
            and not compiled.action_ids
            and compiled.reason_code is None
        ):
            return OperationsResponsePlanResult(
                reference=self._reference(compiled, "model_compiled", None),
                model=response.model,
                used_fallback=False,
                decision_reason=(
                    "模型候选已通过严格 Schema 和服务端编译；该计划仅为建议，未执行动作。"
                ),
            )
        reason_code = compiled.reason_code or "operations_report_action_forbidden"
        return self._fallback(run_id, now, reason_code, response.model)

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
            self._context(run_id, now, model),
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
        self, run_id: UUID, now: datetime, model: str | None
    ) -> ResponsePlanCompileContext:
        return ResponsePlanCompileContext(
            tenant_id=self._tenant_id,
            run_id=run_id,
            case_id=None,
            model_id=model,
            prompt_policy_version=_PROMPT_POLICY_VERSION,
            now=now,
        )

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
