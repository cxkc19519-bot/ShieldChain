"""Run the fixed RAG evaluation against the bundled curated knowledge pack."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import date
from pathlib import Path
from uuid import UUID

from shieldchain.rag.curated_pack import import_curated_pack
from shieldchain.rag.local_service import LocalKnowledgeService
from shieldchain.rag.schemas import EvaluationRequest

_TENANT_ID = UUID("00000000-0000-4000-8000-000000000001")
_PRINCIPAL_ID = UUID("00000000-0000-4000-8000-000000000002")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import the curated security pack and run the fixed RAG evaluation."
    )
    parser.add_argument(
        "--pack-root",
        type=Path,
        default=Path("sample_docs/security_vertical"),
    )
    parser.add_argument(
        "--dataset-id",
        default="shieldchain-security-vertical-v1",
    )
    parser.add_argument("--max-cases", type=int, default=100)
    parser.add_argument(
        "--as-of",
        type=date.fromisoformat,
        default=date.today(),
        help="Manifest review date in YYYY-MM-DD form.",
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        help="Keep evaluation state here instead of using an isolated temporary directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Also write the final result as UTF-8 JSON to this file.",
    )
    return parser.parse_args()


def _evaluate(arguments: argparse.Namespace, data_root: Path) -> dict[str, object]:
    pack_root = arguments.pack_root.resolve(strict=True)
    evaluation_root = (pack_root / "evaluation").resolve(strict=True)
    knowledge = LocalKnowledgeService(
        data_root / "knowledge",
        evaluation_root=evaluation_root,
    )
    imported = import_curated_pack(
        knowledge,
        pack_root,
        tenant_id=_TENANT_ID,
        as_of=arguments.as_of,
    )
    result = knowledge.evaluate(
        EvaluationRequest(
            dataset_id=arguments.dataset_id,
            knowledge_base_ids=[imported.knowledge_base_id],
            max_cases=arguments.max_cases,
        ),
        tenant_id=_TENANT_ID,
        principal_id=_PRINCIPAL_ID,
    )
    payload = result.model_dump(mode="json")
    payload["curated_documents_imported"] = len(imported.imported)
    return payload


def main() -> None:
    arguments = _arguments()
    if arguments.data_root is not None:
        root = arguments.data_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        payload = _evaluate(arguments, root)
    else:
        with tempfile.TemporaryDirectory(prefix="shieldchain-rag-eval-") as raw:
            payload = _evaluate(arguments, Path(raw))
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    if arguments.output is not None:
        destination = arguments.output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
