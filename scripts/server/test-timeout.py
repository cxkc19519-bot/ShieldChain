import unittest
from types import SimpleNamespace
import httpx
from shieldchain.llm.deepseek import DeepSeekClient
from shieldchain.llm.ports import ChatRequest, ChatMessage

class TimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def check_timeout(self, expected, **options):
        async def deadline(coro, seconds):
            self.assertEqual(seconds, expected)
            return await coro
        def handler(request):
            self.assertEqual(request.extensions['timeout']['read'], expected)
            return httpx.Response(200, json={'choices':[{'message':{'content':'OK'}}], 'model':'test', 'usage':{'prompt_tokens':1, 'completion_tokens':1}})
        settings = SimpleNamespace(deepseek_base_url='http://test/v1', deepseek_model='test', deepseek_api_key=SimpleNamespace(get_secret_value=lambda:'test'))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await DeepSeekClient(settings, client, deadline=deadline, **options).chat(ChatRequest(messages=(ChatMessage(role='user', content='hi'),)))
            self.assertEqual(result.content, 'OK')
    async def test_default_unchanged(self):
        await self.check_timeout(30)
    async def test_model_test_override(self):
        await self.check_timeout(120, request_timeout=120)

if __name__ == '__main__': unittest.main()
