"""Download and locate the local BGE models used by ShieldChain RAG."""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable
from pathlib import Path

EMBEDDING_REPOSITORY = "BAAI/bge-m3"
RERANKER_REPOSITORY = "BAAI/bge-reranker-v2-m3"


def models_root(value: str | Path | None = None) -> Path:
    selected = value or os.environ.get("SHIELDCHAIN_RAG_MODELS_ROOT") or "data/models"
    return Path(selected).expanduser().resolve()


def embedding_model_path(root: str | Path | None = None) -> Path:
    return models_root(root) / "bge-m3"


def reranker_model_path(root: str | Path | None = None) -> Path:
    return models_root(root) / "bge-reranker-v2-m3"


def models_are_present(root: str | Path | None = None) -> bool:
    return (embedding_model_path(root) / "config.json").is_file() and (
        reranker_model_path(root) / "config.json"
    ).is_file()


def download_models(
    root: str | Path | None = None, *, progress: Callable[[str], None] = print
) -> tuple[Path, Path]:
    """Materialize both public BGE repositories under one explicit local root."""
    try:
        from huggingface_hub import snapshot_download
    except ImportError as error:  # pragma: no cover
        raise RuntimeError(
            "huggingface_hub is required; install backend[local-rag] first"
        ) from error
    target_root = models_root(root)
    target_root.mkdir(parents=True, exist_ok=True)
    destinations = (
        (EMBEDDING_REPOSITORY, embedding_model_path(target_root)),
        (RERANKER_REPOSITORY, reranker_model_path(target_root)),
    )
    for repository, destination in destinations:
        progress(f"Downloading {repository} to {destination}")
        snapshot_download(repo_id=repository, local_dir=destination)
    return embedding_model_path(target_root), reranker_model_path(target_root)


def main() -> int:
    parser = argparse.ArgumentParser(description="Download ShieldChain local RAG models.")
    parser.add_argument("--root", help="Directory in which model weights are stored.")
    args = parser.parse_args()
    embedding, reranker = download_models(args.root)
    print(f"Embedding model ready: {embedding}")
    print(f"Reranker model ready: {reranker}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
