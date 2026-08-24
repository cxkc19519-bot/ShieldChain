from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url
from shieldchain.main import create_app
from shieldchain.rag.api_service import KnowledgeAccessDenied, UploadedDocument
from shieldchain.rag.schemas import (
    CitationView,
    CreateKnowledgeBaseRequest,
    DocumentVersionListResponse,
    DocumentVersionView,
    EvaluationRequest,
    EvaluationResponse,
    KnowledgeBaseDeleteResponse,
    KnowledgeBaseView,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentView,
    LifecycleOperationResponse,
    RetrievalHitView,
    RetrievalRequest,
    RetrievalResponse,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000101")
PRINCIPAL = UUID("00000000-0000-4000-8000-000000000102")
BASE = uuid4()
DOCUMENT = uuid4()
VERSION = uuid4()


def version() -> DocumentVersionView:
    return DocumentVersionView(
        id=VERSION,
        document_id=DOCUMENT,
        version_number=1,
        parsing_status="succeeded",
        chunking_status="succeeded",
        index_status="succeeded",
        chunking_strategy="semantic-v1",
        created_at=NOW,
        published_at=None,
    )


def document() -> KnowledgeDocumentView:
    return KnowledgeDocumentView(
        id=DOCUMENT,
        knowledge_base_id=BASE,
        original_filename="guide.pdf",
        media_type="application/pdf",
        status="draft",
        current_version_id=None,
        created_at=NOW,
        updated_at=NOW,
        versions=[version()],
    )


class FakeKnowledgeService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, UUID, UUID | None]] = []
        self.upload: UploadedDocument | None = None

    @staticmethod
    def _base() -> KnowledgeBaseView:
        return KnowledgeBaseView(
            id=BASE,
            name="SOC runbooks",
            status="draft",
            default_sensitivity="internal",
            version_policy="immutable",
            created_at=NOW,
            updated_at=NOW,
        )

    def list_knowledge_bases(self, *, tenant_id: UUID):
        self.calls.append(("list_bases", tenant_id, None))
        return [self._base()]

    def create_knowledge_base(self, payload: CreateKnowledgeBaseRequest, *, tenant_id: UUID):
        self.calls.append(("create_base", tenant_id, None))
        return self._base().model_copy(update={"name": payload.name})

    def delete_knowledge_base(self, knowledge_base_id: UUID, *, tenant_id: UUID):
        self.calls.append(('delete_base', tenant_id, knowledge_base_id))
        return KnowledgeBaseDeleteResponse(id=knowledge_base_id, status='completed')

    def upload_document(
        self, knowledge_base_id: UUID, upload: UploadedDocument, *, tenant_id: UUID
    ):
        self.calls.append(("upload", tenant_id, knowledge_base_id))
        self.upload = upload
        return document()

    def list_documents(self, knowledge_base_id: UUID, *, tenant_id: UUID):
        self.calls.append(("list_documents", tenant_id, knowledge_base_id))
        if knowledge_base_id != BASE:
            raise KnowledgeAccessDenied
        return KnowledgeDocumentListResponse(items=[document()])

    def list_versions(self, document_id: UUID, *, tenant_id: UUID):
        self.calls.append(("versions", tenant_id, document_id))
        return DocumentVersionListResponse(document=document(), items=[version()])

    def _operation(self, name: str, document_id: UUID, version_id: UUID | None, tenant_id: UUID):
        self.calls.append((name, tenant_id, document_id))
        return LifecycleOperationResponse(
            operation=name,  # type: ignore[arg-type]
            status="accepted",
            document_id=document_id,
            version_id=version_id,
        )

    def publish(self, document_id: UUID, version_id: UUID, *, tenant_id: UUID):
        return self._operation("publish", document_id, version_id, tenant_id)

    def rollback(self, document_id: UUID, version_id: UUID, *, tenant_id: UUID):
        return self._operation("rollback", document_id, version_id, tenant_id)

    def rebuild(self, document_id: UUID, version_id: UUID, *, tenant_id: UUID):
        return self._operation("rebuild", document_id, version_id, tenant_id)

    def delete(self, document_id: UUID, *, tenant_id: UUID):
        return self._operation("delete", document_id, None, tenant_id)

    def retrieve(self, payload: RetrievalRequest, *, tenant_id: UUID, principal_id: UUID):
        self.calls.append(("retrieve", tenant_id, principal_id))
        return RetrievalResponse(
            query=payload.query,
            answer=None,
            refusal_reason="insufficient_evidence",
            hits=[],
            citations=[],
            degradations=[],
        )

    def evaluate(self, payload: EvaluationRequest, *, tenant_id: UUID, principal_id: UUID):
        self.calls.append(("evaluate", tenant_id, principal_id))
        return EvaluationResponse(
            dataset_id=payload.dataset_id,
            dataset_version="v1",
            case_count=1,
            metrics={"recall_at_k": 1.0},
            quality_gate_passed=True,
        )


@pytest.fixture
def knowledge_client(tmp_path: Path) -> Iterator[tuple[TestClient, FakeKnowledgeService]]:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'knowledge-api.db'}")
    Base.metadata.create_all(engine)
    service = FakeKnowledgeService()
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'knowledge-api.db'}",
        rag_demo_tenant_id=TENANT,
        rag_demo_principal_id=PRINCIPAL,
        simulation_step_delay_ms=0,
    )
    with TestClient(
        create_app(database_engine=engine, settings=settings, knowledge_api_service=service)
    ) as client:
        yield client, service
    engine.dispose()


def test_base_document_and_upload_contract_is_server_tenant_bound(knowledge_client) -> None:
    client, service = knowledge_client
    created = client.post(
        "/api/v1/knowledge-bases",
        json={"name": "New runbooks", "default_sensitivity": "internal"},
    )
    assert created.status_code == 201
    assert "tenant_id" not in created.json()
    assert client.get("/api/v1/knowledge-bases").json()["items"][0]["id"] == str(BASE)
    listed = client.get(f"/api/v1/knowledge-bases/{BASE}/documents")
    assert listed.status_code == 200
    assert listed.json()["items"][0]["versions"][0]["index_status"] == "succeeded"

    uploaded = client.post(
        f"/api/v1/knowledge-bases/{BASE}/documents",
        files={"file": ("guide.pdf", b"safe bytes", "application/pdf")},
        data={"sensitivity": "confidential", "permission_tags": "soc,blue-team"},
    )
    assert uploaded.status_code == 202
    assert service.upload == UploadedDocument(
        "guide.pdf", "application/pdf", b"safe bytes", "confidential", ("soc", "blue-team")
    )
    assert all(call[1] == TENANT for call in service.calls if call[0] != "evaluate")



def test_delete_knowledge_base_contract_is_server_tenant_bound(knowledge_client) -> None:
    client, service = knowledge_client

    deleted = client.delete(f'/api/v1/knowledge-bases/{BASE}')

    assert deleted.status_code == 202
    assert deleted.json() == {'id': str(BASE), 'status': 'completed'}
    assert ('delete_base', TENANT, BASE) in service.calls

def test_versions_lifecycle_retrieval_and_evaluation_contract(knowledge_client) -> None:
    client, service = knowledge_client
    assert client.get(f"/api/v1/documents/{DOCUMENT}/versions").status_code == 200
    for operation in ("publish", "rollback", "rebuild"):
        response = client.post(
            f"/api/v1/documents/{DOCUMENT}/versions/{VERSION}/{operation}"
        )
        assert response.status_code == 202
        assert response.json()["operation"] == operation
    assert client.delete(f"/api/v1/documents/{DOCUMENT}").status_code == 202

    retrieval = client.post(
        "/api/v1/rag/retrieval",
        json={"query": "How to triage?", "knowledge_base_ids": [str(BASE)]},
    )
    assert retrieval.status_code == 200
    assert retrieval.json()["refusal_reason"] == "insufficient_evidence"
    evaluation = client.post(
        "/api/v1/rag/evaluations", json={"dataset_id": "security-bilingual-v1"}
    )
    assert evaluation.status_code == 200
    assert evaluation.json()["quality_gate_passed"] is True
    assert ("retrieve", TENANT, PRINCIPAL) in service.calls
    assert ("evaluate", TENANT, PRINCIPAL) in service.calls


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/v1/knowledge-bases", {"name": "x", "tenant_id": str(uuid4())}),
        (
            "/api/v1/rag/retrieval",
            {"query": "x", "knowledge_base_ids": [str(BASE)], "tenant_id": str(uuid4())},
        ),
    ],
)
def test_json_endpoints_reject_client_tenant(path, payload, knowledge_client) -> None:
    client, _service = knowledge_client
    assert client.post(path, json=payload).status_code == 422


@pytest.mark.parametrize(
    ("filename", "data"),
    [
        ("https://evil.invalid/file.pdf", {}),
        ("safe.pdf", {"path": "C:\\secret.txt"}),
        ("safe.pdf", {"source_url": "https://evil.invalid"}),
        ("safe.pdf", {"tenant_id": str(uuid4())}),
        ("safe.pdf", {"parser_command": "run anything"}),
    ],
)
def test_upload_rejects_paths_urls_commands_and_tenant(filename, data, knowledge_client) -> None:
    client, service = knowledge_client
    response = client.post(
        f"/api/v1/knowledge-bases/{BASE}/documents",
        files={"file": (filename, b"bytes", "application/pdf")},
        data=data,
    )
    assert response.status_code == 422
    assert service.upload is None


@pytest.mark.parametrize(
    ("filename", "media_type"),
    [
        ("payload.exe", "application/octet-stream"),
        ("guide.pdf", "application/octet-stream"),
        ("guide.docx", "application/zip"),
    ],
)
def test_upload_rejects_unsupported_extensions_and_mime_types(
    filename: str, media_type: str, knowledge_client
) -> None:
    client, service = knowledge_client
    response = client.post(
        f"/api/v1/knowledge-bases/{BASE}/documents",
        files={"file": (filename, b"untrusted", media_type)},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "unsupported_document"
    assert service.upload is None


def test_upload_rejects_streamed_body_without_content_length_before_parsing(
    knowledge_client,
) -> None:
    client, service = knowledge_client

    def streamed_body():
        yield b"--boundary\r\n"
        yield b'Content-Disposition: form-data; name="file"; filename="safe.pdf"\r\n'
        yield b"Content-Type: application/pdf\r\n\r\nbytes\r\n--boundary--\r\n"

    response = client.post(
        f"/api/v1/knowledge-bases/{BASE}/documents",
        content=streamed_body(),
        headers={"Content-Type": "multipart/form-data; boundary=boundary"},
    )

    assert response.status_code == 411
    assert response.json()["error"]["code"] == "content_length_required"
    assert service.upload is None


def test_cross_tenant_style_resource_is_not_disclosed(knowledge_client) -> None:
    client, _service = knowledge_client
    response = client.get(
        f"/api/v1/knowledge-bases/{uuid4()}/documents",
        headers={"X-Request-ID": "cross-tenant"},
    )
    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "knowledge_not_found",
            "message": "Knowledge resource not found",
            "request_id": "cross-tenant",
        }
    }


def test_default_local_service_starts_with_an_empty_catalog(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'unconfigured.db'}")
    Base.metadata.create_all(engine)
    app = create_app(database_engine=engine, settings=Settings(_env_file=None))
    with TestClient(app) as client:
        response = client.get("/api/v1/knowledge-bases")
    assert response.status_code == 200
    assert response.json() == {"items": []}
    engine.dispose()


def test_evidence_schema_preserves_native_bm25_and_all_citation_scores() -> None:
    digest = "a" * 64
    hit = RetrievalHitView(
        chunk_id=uuid4(),
        knowledge_base_id=BASE,
        document_id=DOCUMENT,
        document_version_id=VERSION,
        document_title="SOC guide",
        excerpt="evidence",
        heading_path=["Triage"],
        page_number=2,
        structural_location="section:Triage",
        bm25_score=12.75,
        vector_score=0.8,
        fusion_score=0.6,
        reranker_score=0.9,
        updated_at=NOW,
        integrity_sha256=digest,
    )
    citation = CitationView(
        citation_id="citation-1",
        knowledge_base_id=BASE,
        document_id=DOCUMENT,
        document_version_id=VERSION,
        chunk_id=hit.chunk_id,
        document_title="SOC guide",
        heading_path=["Triage"],
        page_number=2,
        structural_location="section:Triage",
        excerpt="evidence",
        bm25_score=hit.bm25_score,
        vector_score=hit.vector_score,
        fusion_score=hit.fusion_score,
        reranker_score=hit.reranker_score,
        updated_at=NOW,
        integrity_sha256=digest,
    )

    assert hit.bm25_score == 12.75
    assert citation.model_dump()["bm25_score"] == 12.75
    assert set(citation.model_dump()) >= {
        "bm25_score",
        "vector_score",
        "fusion_score",
        "reranker_score",
    }
