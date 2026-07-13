import os

import httpx
import pytest

from shieldchain.core.config import Settings
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatMessage, ChatRequest


@pytest.mark.asyncio
async def test_deepseek_live_smoke() -> None:
    if os.getenv("RUN_LIVE_DEEPSEEK_TEST") != "1":
        pytest.skip("set RUN_LIVE_DEEPSEEK_TEST=1 to enable the paid live smoke test")

    settings = Settings()
    if not settings.deepseek_api_key.get_secret_value():
        pytest.skip("a non-empty DEEPSEEK_API_KEY is required for the live smoke test")

    async with httpx.AsyncClient() as http_client:
        response = await DeepSeekClient(settings, http_client).chat(
            ChatRequest(messages=(ChatMessage(role="user", content="Reply with OK"),))
        )

    assert response.content.strip()
