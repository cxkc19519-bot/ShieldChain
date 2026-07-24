"""Run the fixed Phase 8 baseline without network, cloud models, or devices."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi.testclient import TestClient

from shieldchain.main import create_app
from shieldchain.quality.baseline import load_baseline_budget, run_baseline
from shieldchain.rag.evaluation import load_evaluation_dataset


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    budget = load_baseline_budget(
        root / "tests" / "fixtures" / "quality" / "phase8_baseline_v1.json"
    )
    dataset_path = (
        root
        / "backend"
        / "tests"
        / "fixtures"
        / "rag"
        / "evaluation"
        / "security_bilingual_v1.json"
    )
    client = TestClient(create_app())

    def health_live_http() -> None:
        response = client.get("/api/v1/health/live")
        if response.status_code != 200 or response.json() != {"status": "ok"}:
            raise RuntimeError("health live contract failed during baseline")

    def rag_dataset_load() -> None:
        dataset = load_evaluation_dataset(dataset_path)
        if len(dataset.cases) != 6:
            raise RuntimeError("fixed RAG dataset contract changed")

    report = run_baseline(
        budget,
        {
            "health_live_http": health_live_http,
            "rag_dataset_load": rag_dataset_load,
        },
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    print("NETWORK_ACCESS_TESTED=False")
    print("REAL_MODEL_PLANNING_TESTED=False")
    print("REAL_DEVICE_PATHS_TESTED=False")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
