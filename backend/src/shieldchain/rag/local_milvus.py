"""Create and validate the Milvus collection used by ShieldChain RAG."""

from __future__ import annotations

import argparse
from typing import Any

from shieldchain.rag.milvus import MILVUS_SCHEMA

DEFAULT_COLLECTION = "shieldchain_chunks"


class MilvusCollectionError(RuntimeError):
    """The live collection does not meet the immutable ShieldChain contract."""


def collection_fields() -> tuple[str, ...]:
    return tuple(MILVUS_SCHEMA)


def ensure_collection(
    *, uri: str = "http://127.0.0.1:19530", collection: str = DEFAULT_COLLECTION
) -> None:
    """Create the fixed 1024-dimension COSINE collection, never replacing data."""
    if not collection.strip():
        raise ValueError("collection must not be empty")
    try:
        from pymilvus import DataType, MilvusClient
    except ImportError as error:  # pragma: no cover - installation concern
        raise RuntimeError("pymilvus is required; install backend[local-rag] first") from error

    client = MilvusClient(uri=uri)
    if client.has_collection(collection):
        _validate_collection(client.describe_collection(collection), collection)
        return

    schema = client.create_schema(auto_id=False, enable_dynamic_field=False)
    schema.add_field("id", DataType.VARCHAR, is_primary=True, max_length=36)
    schema.add_field("vector", DataType.FLOAT_VECTOR, dim=1024)
    for name in ("tenant_id", "knowledge_base_id", "document_id", "document_version_id"):
        schema.add_field(name, DataType.VARCHAR, max_length=36)
    schema.add_field("sensitivity", DataType.VARCHAR, max_length=32)
    schema.add_field(
        "permission_tags",
        DataType.ARRAY,
        element_type=DataType.VARCHAR,
        max_capacity=16,
        max_length=128,
    )
    schema.add_field("published", DataType.BOOL)
    indexes = client.prepare_index_params()
    indexes.add_index(field_name="vector", index_type="AUTOINDEX", metric_type="COSINE")
    client.create_collection(collection, schema=schema, index_params=indexes)
    _validate_collection(client.describe_collection(collection), collection)


def _validate_collection(description: Any, collection: str) -> None:
    if not isinstance(description, dict):
        raise MilvusCollectionError(f"Milvus collection {collection!r} has no schema")
    fields = description.get("fields")
    if not isinstance(fields, list):
        raise MilvusCollectionError(f"Milvus collection {collection!r} has no fields")
    names = tuple(field.get("name") for field in fields if isinstance(field, dict))
    if names != collection_fields():
        raise MilvusCollectionError(
            f"Milvus collection {collection!r} fields differ from ShieldChain contract"
        )
    by_name = {field["name"]: field for field in fields if isinstance(field, dict)}
    vector = by_name["vector"]
    params = vector.get("params", {})
    if str(params.get("dim")) != "1024":
        raise MilvusCollectionError("Milvus vector dimension must be 1024")


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize the ShieldChain Milvus collection.")
    parser.add_argument("--uri", default="http://127.0.0.1:19530")
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    args = parser.parse_args()
    ensure_collection(uri=args.uri, collection=args.collection)
    print(f"Milvus collection ready: {args.collection}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
