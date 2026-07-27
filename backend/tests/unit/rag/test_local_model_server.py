from __future__ import annotations

from fastapi.testclient import TestClient

from shieldchain.rag.local_model_server import create_model_app


class FakeRuntime:
    root = "D:/models"

    def ready(self) -> bool:
        return True

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[0.0] * 1024 for _ in texts]

    def rerank(self, query: str, documents: list[str]) -> list[float]:
        return [0.75 for _ in documents]


def test_model_service_matches_existing_embedding_and_reranker_contracts() -> None:
    client = TestClient(create_model_app(FakeRuntime()))
    embeddings = client.post("/v1/embeddings", json={"model": "BAAI/bge-m3", "input": ["hello"]})
    reranking = client.post(
        "/v1/rerank",
        json={"model": "BAAI/bge-reranker-v2-m3", "query": "hello", "documents": ["hello world"]},
    )
    assert embeddings.status_code == 200
    assert embeddings.json()["model"] == "BAAI/bge-m3"
    assert len(embeddings.json()["data"][0]["embedding"]) == 1024
    assert reranking.status_code == 200
    assert reranking.json()["data"] == [{"index": 0, "score": 0.75}]
