# Task 5 Report: DeepSeek Port and HTTP Adapter

## Status

Complete. Task 5 adds the transport-independent LLM boundary and a bounded DeepSeek HTTP adapter whose default verification is fully offline.

## Changed Files

- `.env.example`
- `backend/src/shieldchain/llm/__init__.py`
- `backend/src/shieldchain/llm/ports.py`
- `backend/src/shieldchain/llm/deepseek.py`
- `backend/tests/unit/llm/test_deepseek.py`
- `backend/tests/integration/llm/test_deepseek_live.py`
- `development-logs/2026-07-13.md`
- `.superpowers/sdd/task-5-report.md`

## TDD and Verification

- RED: `.\.venv\Scripts\python.exe -m pytest backend\tests\unit\llm\test_deepseek.py -v` collected no tests and reported the expected `ModuleNotFoundError: No module named 'shieldchain.llm'` before production code existed.
- Focused GREEN: `.\.venv\Scripts\python.exe -m pytest backend\tests\unit\llm\test_deepseek.py -v` passed 21 tests.
- Full regression: `.\.venv\Scripts\python.exe -m pytest backend\tests -q` passed 47 tests and skipped 1 guarded live test.
- Live guard only: `.\.venv\Scripts\python.exe -m pytest backend\tests\integration\llm\test_deepseek_live.py -v` reported 1 skipped because `RUN_LIVE_DEEPSEEK_TEST` was unset. The paid live test was not run and no network request was made.
- Ruff: `.\.venv\Scripts\python.exe -m ruff check backend` completed with `All checks passed!`.
- Whitespace: `git diff --check` found no whitespace errors.

## Commit

`feat: add bounded DeepSeek adapter` (this Task 5 commit)

## Self-Review

- Business-facing types and protocol contain no DeepSeek or HTTP details and are frozen dataclasses.
- Request construction validates role, trimmed content, message presence, temperature, and token bounds before an HTTP client can be called.
- The adapter posts the exact configured model/message contract to the normalized `/chat/completions` endpoint with a 30-second total HTTPX timeout.
- HTTP 400/401/403 and malformed successful responses are never retried; 429, 5xx, and connect/read timeouts receive only the injected 0.5- and 1.0-second delays.
- Typed errors distinguish authentication, exhausted rate limiting, unavailability, and invalid responses.
- Attempt logs contain only model, attempt, latency, status category, and numeric prompt/completion counts. Tests assert that the key, authorization data, prompt/messages, and response content are absent.
- Every default adapter test uses HTTPX `MockTransport`; the only non-mock test skips before client construction unless both explicit opt-in and a non-empty key are present.
- No RAG, agent, tool, frontend, provider SDK, secret fixture, or unrelated refactor was added.

## Concerns

- The paid live smoke test was intentionally not run, so real DeepSeek availability and account configuration remain unverified.
- The inherited narrowly scoped Starlette `TestClient` warning filter remains unchanged.

## Review Fix: Overall Deadline and Defensive Request Immutability

### Changes

- Wrapped the complete DeepSeek operation, including every HTTP attempt and injected retry backoff, in an injectable `asyncio.wait_for` deadline of exactly 30.0 seconds.
- Mapped overall deadline expiry to the fixed `LlmUnavailableError("LLM request deadline exceeded")` without logging or returning request/response content.
- Normalized every supplied `ChatRequest.messages` iterable to a tuple in frozen-dataclass initialization before validation, preventing later caller-list mutation from altering the request.

### TDD and Verification

- Deadline RED: `.\.venv\Scripts\python.exe -m pytest backend\tests\unit\llm\test_deepseek.py::test_overall_deadline_cuts_off_retry_backoff_without_real_sleep -v` failed with `TypeError: DeepSeekClient.__init__() got an unexpected keyword argument 'deadline'`.
- Deadline GREEN: the same targeted command passed 1 test. Its deterministic boundary cancelled a retry blocked in injected backoff without real sleeping and asserted the fixed safe error and absence of secret/prompt content.
- Immutability RED: `.\.venv\Scripts\python.exe -m pytest backend\tests\unit\llm\test_deepseek.py::test_chat_request_normalizes_message_list_to_tuple backend\tests\unit\llm\test_deepseek.py::test_chat_request_does_not_retain_caller_message_list -v` failed 2 tests because the request retained the source list.
- Immutability GREEN: the same targeted command passed 2 tests after tuple normalization.
- Focused regression: `.\.venv\Scripts\python.exe -m pytest backend\tests\unit\llm\test_deepseek.py -v` passed 24 tests.
- Full regression: `.\.venv\Scripts\python.exe -m pytest backend\tests -q` passed 50 tests and skipped 1 guarded live test; the live test was not run and no network request was made.
- Ruff: `.\.venv\Scripts\python.exe -m ruff check backend` completed with `All checks passed!`.
- Whitespace: `git diff --check` found no whitespace errors.

### Review-Fix Concerns

- Real DeepSeek connectivity remains intentionally unverified because the paid live smoke test stayed disabled.
- No additional concerns identified within the two requested review fixes.
