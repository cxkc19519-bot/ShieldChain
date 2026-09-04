from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from shieldchain.assistant.evaluation import load_assistant_evaluation_dataset
from shieldchain.assistant.schemas import AssistantEvaluationRequest
from shieldchain.assistant.service import (
    AssistantEvaluationRejected,
    GroundedAssistantService,
    _AssistantTurn,
)
from shieldchain.assistant.store import LocalConversationStore

PACK_ROOT = Path(__file__).parents[4] / "sample_docs" / "security_vertical"
DATASET_ROOT = PACK_ROOT / "evaluation"


def _write_dataset(root: Path) -> None:
    root.mkdir()
    (root / "assistant-test-v1.json").write_text(
        json.dumps(
            {
                "dataset_id": "assistant-test-v1",
                "version": "1.0.0",
                "cases": [
                    {
                        "case_id": "zh-greeting",
                        "language": "zh",
                        "message": "你好",
                        "expected_statuses": ["conversational"],
                        "expected_refusal_reason": None,
                        "expected_document_ids": [],
                    },
                    {
                        "case_id": "en-unknown",
                        "language": "en",
                        "message": "UNKNOWN-9988",
                        "expected_statuses": ["refused"],
                        "expected_refusal_reason": "insufficient_evidence",
                        "expected_document_ids": [],
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


class EvaluationAssistant(GroundedAssistantService):
    def __init__(self, root: Path, evaluation_root: Path) -> None:
        super().__init__(
            object(),
            object(),
            settings=SimpleNamespace(rag_evaluation_root=evaluation_root),
            tenant_id=uuid4(),
            principal_id=uuid4(),
            store=LocalConversationStore(root),
        )

    def sync_historical_reports(self) -> int:
        return 0

    async def _respond(self, message, history, memory_summary):
        del history, memory_summary
        if message == "你好":
            return _AssistantTurn("你好", None, (), "conversational", None, ())
        return _AssistantTurn(
            "没有依据",
            None,
            (),
            "refused",
            "insufficient_evidence",
            (),
        )


def test_fixed_assistant_dataset_is_bilingual_and_pack_bound() -> None:
    dataset = load_assistant_evaluation_dataset(
        DATASET_ROOT / "shieldchain-assistant-v1.json"
    )
    manifest = json.loads((PACK_ROOT / "manifest.json").read_text(encoding="utf-8"))
    filenames = {item["filename"] for item in manifest["documents"]}

    assert dataset.version == "1.0.0"
    assert len(dataset.cases) == 8
    assert {case.language for case in dataset.cases} == {"zh", "en"}
    assert {
        document
        for case in dataset.cases
        for document in case.expected_document_ids
    } <= filenames
    assert {case.expected_refusal_reason for case in dataset.cases} >= {
        "insufficient_evidence",
        "unsafe_content",
    }


def test_assistant_evaluation_runs_without_persisting_conversations(tmp_path: Path) -> None:
    evaluation_root = tmp_path / "evaluation"
    _write_dataset(evaluation_root)
    service = EvaluationAssistant(tmp_path / "conversations", evaluation_root)

    result = asyncio.run(
        service.evaluate(AssistantEvaluationRequest(dataset_id="assistant-test-v1"))
    )

    assert result.case_count == 2
    assert result.metrics["status_accuracy"] == 1.0
    assert result.metrics["refusal_accuracy"] == 1.0
    assert result.metrics["case_pass_rate"] == 1.0
    assert result.quality_gate_passed is True
    assert all(case.passed for case in result.case_results)
    assert service.conversations() == []


def test_assistant_evaluation_rejects_unknown_dataset(tmp_path: Path) -> None:
    evaluation_root = tmp_path / "evaluation"
    evaluation_root.mkdir()
    service = EvaluationAssistant(tmp_path / "conversations", evaluation_root)

    with pytest.raises(AssistantEvaluationRejected, match="unavailable"):
        asyncio.run(
            service.evaluate(AssistantEvaluationRequest(dataset_id="missing-v1"))
        )
