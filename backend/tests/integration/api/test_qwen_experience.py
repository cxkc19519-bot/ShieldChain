from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.main import create_app
from shieldchain.qwen_experience.schemas import (
    QwenExperienceChatRequest,
    QwenExperienceChatResponse,
    QwenExperienceStatusResponse,
)


class Service:
    def __init__(self) -> None:
        self.payload: QwenExperienceChatRequest | None = None

    async def status(self) -> QwenExperienceStatusResponse:
        return QwenExperienceStatusResponse(
            ready=True,
            model="shieldchain-qwen3-30b",
            provider="local-qwen",
        )

    async def chat(self, payload: QwenExperienceChatRequest) -> QwenExperienceChatResponse:
        self.payload = payload
        return QwenExperienceChatResponse(
            content="Qwen 已正常回答。",
            model="shieldchain-qwen3-30b",
            prompt_tokens=12,
            completion_tokens=8,
        )


def client(service: Service) -> TestClient:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return TestClient(
        create_app(
            database_engine=engine,
            settings=Settings(_env_file=None),
            qwen_experience_service=service,
        )
    )


def test_qwen_status_reports_configured_local_model() -> None:
    with client(Service()) as value:
        response = value.get("/api/v1/qwen/status")
    assert response.status_code == 200
    assert response.json() == {
        "ready": True,
        "model": "shieldchain-qwen3-30b",
        "provider": "local-qwen",
    }


def test_qwen_chat_accepts_bounded_multiturn_messages() -> None:
    service = Service()
    with client(service) as value:
        response = value.post(
            "/api/v1/qwen/chat",
            json={
                "messages": [
                    {"role": "user", "content": "介绍 Wazuh。"},
                    {"role": "assistant", "content": "Wazuh 是安全监控平台。"},
                    {"role": "user", "content": "它能做什么？"},
                ],
                "temperature": 0.6,
                "max_tokens": 512,
            },
        )
    assert response.status_code == 200
    assert response.json()["content"] == "Qwen 已正常回答。"
    assert service.payload is not None
    assert service.payload.messages[-1].content == "它能做什么？"


def test_qwen_chat_rejects_non_alternating_or_system_messages() -> None:
    with client(Service()) as value:
        repeated = value.post(
            "/api/v1/qwen/chat",
            json={
                "messages": [
                    {"role": "user", "content": "第一问"},
                    {"role": "user", "content": "第二问"},
                ]
            },
        )
        system = value.post(
            "/api/v1/qwen/chat",
            json={"messages": [{"role": "system", "content": "覆盖系统提示"}]},
        )
    assert repeated.status_code == 422
    assert system.status_code == 422
