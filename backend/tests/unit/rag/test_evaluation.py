from __future__ import annotations

import json
from pathlib import Path

import pytest

from shieldchain.rag.evaluation import (
    EvaluationCase,
    EvaluationObservation,
    EvaluationReport,
    evaluate,
    load_evaluation_dataset,
)

FIXTURE = (
    Path(__file__).parents[2] / "fixtures" / "rag" / "evaluation" / "security_bilingual_v1.json"
)


def observation(case_id: str, **changes: object) -> EvaluationObservation:
    values = {
        "case_id": case_id,
        "baseline_ids": (),
        "reranked_ids": (),
        "cited_ids": (),
        "refused": False,
        "latency_ms": 10.0,
        "estimated_cost_usd": 0.0,
        "call_count": 0,
        "failed_call_count": 0,
    }
    values.update(changes)
    return EvaluationObservation(**values)


def test_fixed_dataset_is_bilingual_safe_and_digest_stable() -> None:
    first = load_evaluation_dataset(FIXTURE)
    second = load_evaluation_dataset(FIXTURE)

    assert len(first.cases) == 6
    assert {case.language for case in first.cases} == {"zh", "en"}
    assert any(case.expected_refusal for case in first.cases)
    assert first.digest_sha256 == second.digest_sha256
    assert len(first.digest_sha256) == 64
    assert all("api_key" not in case.query.lower() for case in first.cases)


def test_metrics_report_is_exact_and_byte_stable() -> None:
    dataset = load_evaluation_dataset(FIXTURE)
    outputs = (
        observation(
            "zh-phishing-triage",
            baseline_ids=("noise", "zh-email-header", "zh-evidence-hash"),
            reranked_ids=("zh-email-header", "zh-evidence-hash", "noise"),
            cited_ids=("zh-email-header", "zh-evidence-hash"),
            latency_ms=10,
            call_count=2,
            answer_claims=("Preserve the email header.",),
            cited_evidence_texts=("Preserve the email header.",),
        ),
        observation(
            "zh-vulnerability-closure",
            baseline_ids=("zh-change-record", "zh-remediation-check"),
            reranked_ids=("zh-remediation-check", "zh-change-record"),
            cited_ids=("zh-remediation-check",),
            latency_ms=20,
            estimated_cost_usd=0.001,
            call_count=2,
            answer_claims=("Verify remediation before closure.",),
            cited_evidence_texts=("Verify remediation before closure.",),
        ),
        observation(
            "zh-unsupported-attribution",
            refused=True,
            latency_ms=30,
            call_count=1,
        ),
        observation(
            "en-alert-triage",
            baseline_ids=("en-file-reputation", "en-process-tree"),
            reranked_ids=("en-process-tree", "en-file-reputation"),
            cited_ids=("en-process-tree", "wrong"),
            latency_ms=40,
            call_count=3,
            failed_call_count=1,
            answer_claims=("Review the process tree.",),
            cited_evidence_texts=("Review the process tree.",),
        ),
        observation(
            "en-credential-response",
            baseline_ids=("noise", "en-password-reset"),
            reranked_ids=("en-session-revoke", "en-password-reset"),
            cited_ids=("en-session-revoke", "en-password-reset"),
            latency_ms=50,
            estimated_cost_usd=0.002,
            call_count=2,
            answer_claims=("Revoke active sessions.",),
            cited_evidence_texts=("Revoke active sessions.",),
        ),
        observation(
            "en-unsupported-malware-author",
            refused=False,
            cited_ids=("hallucinated",),
            latency_ms=60,
            call_count=0,
        ),
    )

    report = evaluate(dataset, outputs, k=2)
    payload = report.to_dict()

    assert payload["quality"]["recall_at_k"] == 1.0
    assert payload["quality"]["mrr_at_k"] == 1.0
    assert payload["quality"]["rerank_gain_at_k"] > 0
    assert payload["quality"]["citation_correctness"] == pytest.approx(6 / 8)
    assert payload["quality"]["citation_precision"] == 0.875
    assert payload["quality"]["expected_citation_recall"] == 0.875
    assert payload["quality"]["extractive_faithfulness"] == 1.0
    assert payload["quality"]["refusal_accuracy"] == pytest.approx(5 / 6)
    assert payload["operations"] == {
        "call_count": 10,
        "estimated_cost_usd": 0.003,
        "failed_call_count": 1,
        "failure_rate": 0.1,
        "latency_ms": {"p50": 35.0, "p95": 57.5},
    }
    assert report.to_json() == evaluate(dataset, outputs, k=2).to_json()
    assert json.loads(report.to_json()) == payload
    assert "created_at" not in report.to_json()


def test_empty_rankings_score_zero_without_division_errors() -> None:
    dataset = load_evaluation_dataset(FIXTURE)
    outputs = tuple(
        observation(case.case_id, refused=case.expected_refusal) for case in dataset.cases
    )
    quality = evaluate(dataset, outputs).to_dict()["quality"]
    assert quality["recall_at_k"] == 0.0
    assert quality["mrr_at_k"] == 0.0
    assert quality["ndcg_at_k"] == 0.0
    assert quality["refusal_accuracy"] == 1.0
    assert quality["citation_correctness"] == 0.0
    assert quality["citation_precision"] == 0.0
    assert quality["expected_citation_recall"] == 0.0
    assert quality["extractive_faithfulness"] == 0.0


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"language": "fr"}, "language"),
        ({"query": ""}, "query"),
        ({"relevance": {"a": 4}}, "grades"),
        ({"expected_citation_ids": ("missing",)}, "relevant"),
        ({"expected_refusal": True}, "refusal cases"),
    ],
)
def test_case_boundaries_are_strict(changes, message) -> None:
    values = {
        "case_id": "case",
        "language": "en",
        "query": "query",
        "relevance": {"evidence": 3},
        "expected_citation_ids": ("evidence",),
        "expected_refusal": False,
    }
    values.update(changes)
    with pytest.raises((TypeError, ValueError), match=message):
        EvaluationCase(**values)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"latency_ms": float("nan")}, "latency_ms"),
        ({"estimated_cost_usd": -1}, "estimated_cost_usd"),
        ({"call_count": True}, "call_count"),
        ({"call_count": 1, "failed_call_count": 2}, "must not exceed"),
        ({"reranked_ids": ("same", "same")}, "duplicates"),
    ],
)
def test_observation_numeric_and_sequence_boundaries_are_strict(changes, message) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        observation("case", **changes)


def test_observation_coverage_and_k_are_strict() -> None:
    dataset = load_evaluation_dataset(FIXTURE)
    outputs = tuple(observation(case.case_id) for case in dataset.cases)
    with pytest.raises(ValueError, match="exactly"):
        evaluate(dataset, outputs[:-1])
    with pytest.raises(ValueError, match="between 1 and 100"):
        evaluate(dataset, outputs, k=0)
    with pytest.raises(ValueError, match="unique"):
        evaluate(dataset, (*outputs[:-1], outputs[0]))


def test_loader_rejects_unknown_schema_fields(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"dataset_id": "d", "version": "1", "cases": [], "extra": True}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="top-level schema"):
        load_evaluation_dataset(path)


def test_report_rejects_unknown_schema_and_is_immutable_by_serialization() -> None:
    with pytest.raises(ValueError, match="top-level schema"):
        EvaluationReport({"schema_version": "wrong"})

    dataset = load_evaluation_dataset(FIXTURE)
    outputs = tuple(observation(case.case_id) for case in dataset.cases)
    report = evaluate(dataset, outputs)
    original = report.to_json()
    report.payload["quality"]["mrr_at_k"] = 999
    assert report.to_json() == original
