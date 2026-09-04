"""Run the fixed assistant evaluation against the bundled curated knowledge pack."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from shieldchain.assistant.schemas import AssistantEvaluationRequest
from shieldchain.assistant.service import GroundedAssistantService
from shieldchain.assistant.store import LocalConversationStore
from shieldchain.core.config import Settings
from shieldchain.rag.curated_pack import import_curated_pack
from shieldchain.rag.local_service import LocalKnowledgeService

_TENANT_ID = UUID("00000000-0000-4000-8000-000000000001")
_PRINCIPAL_ID = UUID("00000000-0000-4000-8000-000000000002")


class _EmptyReports:
    """Evaluation fixture: the fixed dataset only targets curated knowledge."""

    @staticmethod
    def historical_reports(limit: int = 100):
        del limit
        return SimpleNamespace(reports=[])


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import the curated security pack and run the fixed assistant evaluation."
    )
    parser.add_argument(
        "--pack-root",
        type=Path,
        default=Path("sample_docs/security_vertical"),
    )
    parser.add_argument(
        "--dataset-id",
        default="shieldchain-assistant-v1",
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
        "--offline",
        action="store_true",
        help="Disable generation calls so the extractive degradation path is measured.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Also write the final result as UTF-8 JSON to this file.",
    )
    return parser.parse_args()


async def _evaluate(
    arguments: argparse.Namespace, data_root: Path
) -> dict[str, object]:
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
    settings_kwargs: dict[str, object] = {"rag_evaluation_root": evaluation_root}
    if arguments.offline:
        settings_kwargs.update(
            deepseek_base_url="http://127.0.0.1:9",
            deepseek_api_key="",
        )
    assistant = GroundedAssistantService(
        knowledge,
        _EmptyReports(),  # type: ignore[arg-type]
        settings=Settings(**settings_kwargs),
        tenant_id=_TENANT_ID,
        principal_id=_PRINCIPAL_ID,
        store=LocalConversationStore(data_root / "assistant"),
    )
    result = await assistant.evaluate(
        AssistantEvaluationRequest(
            dataset_id=arguments.dataset_id,
            max_cases=arguments.max_cases,
        )
    )
    payload = result.model_dump(mode="json")
    payload["curated_documents_imported"] = len(imported.imported)
    payload["evaluation_mode"] = (
        "offline-extractive" if arguments.offline else "configured"
    )
    return payload


def main() -> None:
    arguments = _arguments()
    if arguments.data_root is not None:
        root = arguments.data_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        payload = asyncio.run(_evaluate(arguments, root))
    else:
        with tempfile.TemporaryDirectory(prefix="shieldchain-assistant-eval-") as raw:
            payload = asyncio.run(_evaluate(arguments, Path(raw)))
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    if arguments.output is not None:
        destination = arguments.output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
