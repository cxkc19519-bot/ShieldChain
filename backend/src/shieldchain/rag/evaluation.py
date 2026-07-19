"""Deterministic, offline evaluation for the fixed bilingual RAG benchmark."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

REPORT_SCHEMA_VERSION = "shieldchain.rag.evaluation/v1"
MAX_CASES = 10_000
MAX_RANKED_ITEMS = 1_000
MAX_IDENTIFIER_LENGTH = 200
MAX_QUERY_LENGTH = 8_192
MAX_CALLS_PER_CASE = 10_000
MAX_LATENCY_MS = 86_400_000.0
MAX_COST_USD = 1_000_000.0


def _text(value: object, field: str, *, maximum: int = MAX_IDENTIFIER_LENGTH) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{field} must not have surrounding whitespace")
    if len(value) > maximum:
        raise ValueError(f"{field} must not exceed {maximum} characters")
    return value


def _ids(value: object, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be a sequence")
    if len(value) > MAX_RANKED_ITEMS:
        raise ValueError(f"{field} must not exceed {MAX_RANKED_ITEMS} items")
    result = tuple(_text(item, field) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{field} must not contain duplicates")
    return result


def _finite_number(value: object, field: str, *, minimum: float, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{field} must be finite and between {minimum} and {maximum}")
    return result


def _count(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_CALLS_PER_CASE
    ):
        raise ValueError(f"{field} must be an integer between 0 and {MAX_CALLS_PER_CASE}")
    return value


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    """Trusted benchmark truth for one retrieval or refusal question."""

    case_id: str
    language: str
    query: str
    relevance: Mapping[str, int]
    expected_citation_ids: Sequence[str]
    expected_refusal: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", _text(self.case_id, "case_id"))
        if self.language not in {"zh", "en"}:
            raise ValueError("language must be 'zh' or 'en'")
        object.__setattr__(self, "query", _text(self.query, "query", maximum=MAX_QUERY_LENGTH))
        if not isinstance(self.relevance, Mapping):
            raise TypeError("relevance must be a mapping")
        if len(self.relevance) > MAX_RANKED_ITEMS:
            raise ValueError(f"relevance must not exceed {MAX_RANKED_ITEMS} items")
        relevance: dict[str, int] = {}
        for raw_id, raw_grade in self.relevance.items():
            item_id = _text(raw_id, "relevance key")
            if (
                not isinstance(raw_grade, int)
                or isinstance(raw_grade, bool)
                or not 1 <= raw_grade <= 3
            ):
                raise ValueError("relevance grades must be integers between 1 and 3")
            relevance[item_id] = raw_grade
        citations = _ids(self.expected_citation_ids, "expected_citation_ids")
        if not isinstance(self.expected_refusal, bool):
            raise TypeError("expected_refusal must be a bool")
        if self.expected_refusal and relevance:
            raise ValueError("refusal cases must not declare relevant evidence")
        if self.expected_refusal and citations:
            raise ValueError("refusal cases must not declare expected citations")
        if not self.expected_refusal and not relevance:
            raise ValueError("answerable cases must declare relevant evidence")
        if not set(citations).issubset(relevance):
            raise ValueError("expected citations must be relevant item identifiers")
        object.__setattr__(self, "relevance", relevance)
        object.__setattr__(self, "expected_citation_ids", citations)


@dataclass(frozen=True, slots=True)
class EvaluationObservation:
    """One system output and its bounded operational telemetry."""

    case_id: str
    baseline_ids: Sequence[str]
    reranked_ids: Sequence[str]
    cited_ids: Sequence[str]
    refused: bool
    latency_ms: float
    estimated_cost_usd: float
    call_count: int
    failed_call_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", _text(self.case_id, "case_id"))
        for field_name in ("baseline_ids", "reranked_ids", "cited_ids"):
            object.__setattr__(
                self, field_name, _ids(getattr(self, field_name), field_name)
            )
        if not isinstance(self.refused, bool):
            raise TypeError("refused must be a bool")
        object.__setattr__(
            self,
            "latency_ms",
            _finite_number(self.latency_ms, "latency_ms", minimum=0, maximum=MAX_LATENCY_MS),
        )
        object.__setattr__(
            self,
            "estimated_cost_usd",
            _finite_number(
                self.estimated_cost_usd,
                "estimated_cost_usd",
                minimum=0,
                maximum=MAX_COST_USD,
            ),
        )
        object.__setattr__(self, "call_count", _count(self.call_count, "call_count"))
        object.__setattr__(
            self, "failed_call_count", _count(self.failed_call_count, "failed_call_count")
        )
        if self.failed_call_count > self.call_count:
            raise ValueError("failed_call_count must not exceed call_count")


@dataclass(frozen=True, slots=True)
class EvaluationDataset:
    dataset_id: str
    version: str
    cases: Sequence[EvaluationCase]
    digest_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "dataset_id", _text(self.dataset_id, "dataset_id"))
        object.__setattr__(self, "version", _text(self.version, "version"))
        if isinstance(self.cases, (str, bytes)) or not isinstance(self.cases, Sequence):
            raise TypeError("cases must be a sequence")
        cases = tuple(self.cases)
        if not cases or len(cases) > MAX_CASES:
            raise ValueError(f"cases must contain between 1 and {MAX_CASES} items")
        if any(not isinstance(case, EvaluationCase) for case in cases):
            raise TypeError("cases must contain EvaluationCase values")
        if len({case.case_id for case in cases}) != len(cases):
            raise ValueError("case identifiers must be unique")
        if {case.language for case in cases} != {"zh", "en"}:
            raise ValueError("dataset must contain both Chinese and English cases")
        if (
            not isinstance(self.digest_sha256, str)
            or len(self.digest_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.digest_sha256)
        ):
            raise ValueError("digest_sha256 must be lowercase SHA-256 hexadecimal")
        object.__setattr__(self, "cases", cases)


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Stable report value; serialization deliberately contains no wall-clock timestamp."""

    payload: Mapping[str, Any]
    _serialized: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _validate_report_schema(self.payload)
        try:
            serialized = json.dumps(
                self.payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as error:
            raise ValueError("report payload must be finite JSON data") from error
        object.__setattr__(self, "_serialized", serialized)

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._serialized)

    def to_json(self) -> str:
        return self._serialized


def load_evaluation_dataset(path: str | Path) -> EvaluationDataset:
    """Load a strict JSON benchmark without network access or executable content."""
    source = Path(path)
    raw = source.read_bytes()
    if len(raw) > 10_000_000:
        raise ValueError("evaluation dataset exceeds 10,000,000 bytes")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("evaluation dataset must be valid UTF-8 JSON") from error
    if not isinstance(document, dict) or set(document) != {"dataset_id", "version", "cases"}:
        raise ValueError("evaluation dataset has an invalid top-level schema")
    raw_cases = document["cases"]
    if not isinstance(raw_cases, list):
        raise TypeError("cases must be a JSON array")
    expected_fields = {
        "case_id",
        "language",
        "query",
        "relevance",
        "expected_citation_ids",
        "expected_refusal",
    }
    cases: list[EvaluationCase] = []
    for item in raw_cases:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise ValueError("evaluation case has an invalid schema")
        cases.append(EvaluationCase(**item))
    canonical = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return EvaluationDataset(
        dataset_id=document["dataset_id"],
        version=document["version"],
        cases=cases,
        digest_sha256=sha256(canonical).hexdigest(),
    )


def evaluate(
    dataset: EvaluationDataset,
    observations: Sequence[EvaluationObservation],
    *,
    k: int = 5,
) -> EvaluationReport:
    """Compute deterministic retrieval, citation, refusal, latency, cost and failure metrics."""
    if not isinstance(dataset, EvaluationDataset):
        raise TypeError("dataset must be an EvaluationDataset")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 100:
        raise ValueError("k must be an integer between 1 and 100")
    if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
        raise TypeError("observations must be a sequence")
    values = tuple(observations)
    if any(not isinstance(item, EvaluationObservation) for item in values):
        raise TypeError("observations must contain EvaluationObservation values")
    by_id = {item.case_id: item for item in values}
    if len(by_id) != len(values):
        raise ValueError("observation case identifiers must be unique")
    expected_ids = {case.case_id for case in dataset.cases}
    if set(by_id) != expected_ids:
        raise ValueError("observations must match dataset cases exactly")

    retrieval_cases = [case for case in dataset.cases if case.relevance]
    recall_values: list[float] = []
    reciprocal_ranks: list[float] = []
    baseline_ndcg: list[float] = []
    reranked_ndcg: list[float] = []
    citation_correct = 0
    citation_denominator = 0
    refusal_correct = 0
    latencies: list[float] = []
    total_cost = 0.0
    total_calls = 0
    failed_calls = 0

    for case in dataset.cases:
        observation = by_id[case.case_id]
        latencies.append(observation.latency_ms)
        total_cost += observation.estimated_cost_usd
        total_calls += observation.call_count
        failed_calls += observation.failed_call_count
        refusal_correct += observation.refused == case.expected_refusal

        expected_citations = set(case.expected_citation_ids)
        actual_citations = set(observation.cited_ids)
        citation_correct += len(expected_citations & actual_citations)
        citation_denominator += max(len(expected_citations), len(actual_citations))

        if case.relevance:
            result_ids = observation.reranked_ids[:k]
            relevant = set(case.relevance)
            recall_values.append(len(relevant & set(result_ids)) / len(relevant))
            reciprocal_ranks.append(_reciprocal_rank(result_ids, relevant))
            baseline_ndcg.append(_ndcg(observation.baseline_ids[:k], case.relevance, k))
            reranked_ndcg.append(_ndcg(result_ids, case.relevance, k))

    baseline = _mean(baseline_ndcg)
    reranked = _mean(reranked_ndcg)
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.version,
            "sha256": dataset.digest_sha256,
            "case_count": len(dataset.cases),
            "retrieval_case_count": len(retrieval_cases),
            "languages": sorted({case.language for case in dataset.cases}),
        },
        "configuration": {"k": k},
        "quality": {
            "recall_at_k": _rounded(_mean(recall_values)),
            "mrr_at_k": _rounded(_mean(reciprocal_ranks)),
            "ndcg_at_k": _rounded(reranked),
            "baseline_ndcg_at_k": _rounded(baseline),
            "rerank_gain_at_k": _rounded(reranked - baseline),
            "citation_correctness": _rounded(
                citation_correct / citation_denominator if citation_denominator else 1.0
            ),
            "refusal_accuracy": _rounded(refusal_correct / len(dataset.cases)),
        },
        "operations": {
            "latency_ms": {
                "p50": _rounded(_percentile(latencies, 0.50)),
                "p95": _rounded(_percentile(latencies, 0.95)),
            },
            "call_count": total_calls,
            "failed_call_count": failed_calls,
            "failure_rate": _rounded(failed_calls / total_calls if total_calls else 0.0),
            "estimated_cost_usd": _rounded(total_cost),
        },
    }
    return EvaluationReport(payload)


def _reciprocal_rank(ranked_ids: Sequence[str], relevant: set[str]) -> float:
    for rank, item_id in enumerate(ranked_ids, start=1):
        if item_id in relevant:
            return 1.0 / rank
    return 0.0


def _ndcg(ranked_ids: Sequence[str], relevance: Mapping[str, int], k: int) -> float:
    dcg = sum(
        (2 ** relevance.get(item_id, 0) - 1) / math.log2(rank + 1)
        for rank, item_id in enumerate(ranked_ids[:k], start=1)
    )
    ideal = sorted(relevance.values(), reverse=True)[:k]
    ideal_dcg = sum((2**grade - 1) / math.log2(rank + 1) for rank, grade in enumerate(ideal, 1))
    return dcg / ideal_dcg if ideal_dcg else 0.0


def _mean(values: Sequence[float]) -> float:
    return math.fsum(values) / len(values) if values else 0.0


def _percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _rounded(value: float) -> float:
    result = round(value, 8)
    return 0.0 if result == 0 else result


def _validate_report_schema(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping):
        raise TypeError("report payload must be a mapping")
    expected = {
        "schema_version": None,
        "dataset": {"id", "version", "sha256", "case_count", "retrieval_case_count", "languages"},
        "configuration": {"k"},
        "quality": {
            "recall_at_k",
            "mrr_at_k",
            "ndcg_at_k",
            "baseline_ndcg_at_k",
            "rerank_gain_at_k",
            "citation_correctness",
            "refusal_accuracy",
        },
        "operations": {
            "latency_ms",
            "call_count",
            "failed_call_count",
            "failure_rate",
            "estimated_cost_usd",
        },
    }
    if set(payload) != set(expected) or payload.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError("report payload has an invalid top-level schema")
    for section, fields in expected.items():
        if fields is None:
            continue
        value = payload[section]
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ValueError(f"report payload has an invalid {section} schema")
    latency = payload["operations"]["latency_ms"]
    if not isinstance(latency, Mapping) or set(latency) != {"p50", "p95"}:
        raise ValueError("report payload has an invalid latency schema")
