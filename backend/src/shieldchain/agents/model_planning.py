"""Bounded DeepSeek planning for investigation recommendations."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

import httpx

from shieldchain.core.config import Settings
from shieldchain.incidents.domain import Assessment, Conclusion, Evidence
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest, LlmError

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AutonomousPlan:
    """A proposal that can only reduce automation; it grants no tool authority."""

    allow_execution: bool
    summary: str
    model: str | None


class DeepSeekAutonomousPlanner:
    def __init__(self, settings: Settings | None) -> None:
        self._settings = settings

    def plan(
        self,
        *,
        assessment: Assessment,
        evidence: tuple[Evidence, ...],
        grounded_knowledge: str,
    ) -> AutonomousPlan:
        fallback = AutonomousPlan(
            allow_execution=assessment.conclusion is Conclusion.CONFIRMED_THREAT,
            summary="\u57fa\u4e8e\u786e\u5b9a\u6027\u7814\u5224\u751f\u6210\u53d7\u63a7\u5904\u7f6e\u5efa\u8bae\u3002",
            model=None,
        )
        if self._settings is None or not self._settings.deepseek_api_key.get_secret_value():
            return fallback
        payload = {
            "assessment": assessment.conclusion.value,
            "risk": assessment.risk_level.value,
            "evidence": [item.summary[:240] for item in evidence[:5]],
            "grounded_knowledge": grounded_knowledge[:800],
        }
        request = ChatRequest(
            messages=(
                ChatMessage(
                    role="system",
                    content=(
                        "You are a security response planner. Return JSON only: "
                        '{"decision":"proceed"|"manual_review",'
                        '"reason":"at most 40 Chinese characters"}. '
                        "Deterministic policy permits only trusted-gateway IP blocking. "
                        "Choose proceed only when confirmed_threat and evidence agree; "
                        "otherwise choose manual_review. "
                        "Never invent tools, targets, credentials, commands, or actions."
                    ),
                ),
                ChatMessage(role="user", content=json.dumps(payload, ensure_ascii=False)),
            ),
            temperature=0.0,
            max_tokens=1024,
        )

        async def invoke():
            async with httpx.AsyncClient() as client:
                return await DeepSeekClient(self._settings, client).chat(request)

        try:
            response = asyncio.run(invoke())
            text = response.content.strip()
            start, end = text.find("{"), text.rfind("}")
            parsed = json.loads(text[start : end + 1]) if start >= 0 and end > start else {}
            decision = str(parsed.get("decision", "manual_review"))
            reason = " ".join(str(parsed.get("reason", "")).split())[:240]
            allow_execution = (
                decision == "proceed" and assessment.conclusion is Conclusion.CONFIRMED_THREAT
            )
            default_reason = (
                "\u5efa\u8bae\u7ee7\u7eed\u53d7\u63a7\u5904\u7f6e\u6d41\u7a0b"
                if allow_execution
                else "\u5efa\u8bae\u8f6c\u4eba\u5de5\u590d\u6838"
            )
            return AutonomousPlan(
                allow_execution=allow_execution,
                summary=(
                    "\u54cd\u5e94\u89c4\u5212\u667a\u80fd\u4f53\uff1a" + (reason or default_reason)
                ),
                model=response.model,
            )
        except (LlmError, ValueError, json.JSONDecodeError, RuntimeError):
            return fallback
