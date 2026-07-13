# Phase 1 Engineering Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立可在 Windows 本机稳定启动、可测试、默认安全的 React＋FastAPI 工程基础，并用可替换的 DeepSeek 适配器完成第一条真实外部依赖边界。

**Architecture:** 初版由一个 FastAPI 后端和一个 React 前端组成，SQLite 通过仓储边界保存业务状态。配置、日志、模型调用和健康检查分别封装；所有云端能力均可被测试替身替换，本阶段不实现 RAG、智能体业务或安全工具闭环。

**Tech Stack:** Python 3.12、FastAPI、Pydantic Settings、SQLAlchemy 2、Alembic、HTTPX、Structlog、Pytest、React、TypeScript、Vite、Vitest、Testing Library、ESLint、PowerShell。

## Global Constraints

- 初版必须在 Windows 本机直接运行，不要求 Docker。
- DeepSeek 必须通过 `LlmClient` 端口接入，业务模块不得直接依赖供应商 SDK 或 HTTP API。
- API Key、密码和令牌只能从环境变量读取，不得写入代码、日志、测试夹具或版本库。
- 默认测试不得访问网络或产生真实 API 费用；真实 DeepSeek 冒烟测试必须显式启用。
- 结构化日志必须包含 `request_id`，并对密钥和授权头脱敏。
- 后端使用 `/api/v1` 路径前缀；健康检查为 `/api/v1/health/live` 和 `/api/v1/health/ready`。
- 本阶段只建立工程边界、健康检查、SQLite 基础、DeepSeek 适配器和前端外壳，不提前实现 RAG、多智能体或工具调用。
- 每个任务均按测试先行、最小实现、全量回归、文档与开发日志更新的顺序完成。

---

## Planned File Structure

```text
backend/
├─ pyproject.toml
├─ alembic.ini
├─ src/shieldchain/
│  ├─ __init__.py
│  ├─ main.py                  # FastAPI 应用工厂
│  ├─ api/health.py            # 存活与就绪检查
│  ├─ core/config.py           # 环境配置
│  ├─ core/errors.py           # 稳定错误响应
│  ├─ core/logging.py          # 结构化日志与脱敏
│  ├─ core/request_id.py       # 请求关联 ID 中间件
│  ├─ db/base.py               # SQLAlchemy Base
│  ├─ db/session.py            # SQLite 引擎和会话
│  ├─ llm/ports.py             # LLM 抽象接口和类型
│  └─ llm/deepseek.py          # DeepSeek HTTP 适配器
├─ migrations/                 # Alembic 迁移环境
└─ tests/
   ├─ conftest.py
   ├─ unit/core/
   ├─ unit/llm/
   └─ integration/api/
frontend/
├─ package.json
├─ vite.config.ts
├─ src/
│  ├─ app/App.tsx              # 前端应用外壳
│  ├─ app/router.tsx           # 页面路由
│  ├─ api/client.ts            # 后端 HTTP 客户端
│  ├─ features/dashboard/      # 运营总览占位页面
│  ├─ styles/tokens.css        # 淡蓝色设计令牌
│  └─ test/setup.ts
└─ tests/
scripts/
├─ dev.ps1                     # 同时启动前后端
├─ test.ps1                    # 运行默认无网络测试
└─ verify.ps1                  # 格式、类型、测试和构建
.env.example
.gitignore
README.md
```

---

### Task 1: Repository Guardrails and Backend Health Slice

**Files:**
- Create: `.gitignore`
- Create: `.env.example`
- Create: `backend/pyproject.toml`
- Create: `backend/src/shieldchain/__init__.py`
- Create: `backend/src/shieldchain/main.py`
- Create: `backend/src/shieldchain/api/__init__.py`
- Create: `backend/src/shieldchain/api/health.py`
- Create: `backend/tests/conftest.py`
- Create: `backend/tests/integration/api/test_health.py`
- Modify: `development-logs/2026-07-13.md`

**Interfaces:**
- Produces: `create_app() -> FastAPI`
- Produces: `GET /api/v1/health/live -> {"status": "ok"}`
- Produces: `GET /api/v1/health/ready -> {"status": "ready"}` in the initial dependency-free state

- [ ] **Step 1: Initialize version control only if `.git` is absent**

Run: `git rev-parse --is-inside-work-tree`

Expected before initialization: exit code 128 with “not a git repository”. Then run: `git init`

Expected after initialization: output containing `Initialized empty Git repository`.

- [ ] **Step 2: Write the failing health tests**

```python
from fastapi.testclient import TestClient

from shieldchain.main import create_app


def test_liveness_reports_ok() -> None:
    response = TestClient(create_app()).get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_ready_without_optional_dependencies() -> None:
    response = TestClient(create_app()).get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
```

- [ ] **Step 3: Add the backend package metadata and install the editable test environment**

Use `backend/pyproject.toml` with Python `>=3.12,<3.15`, runtime dependencies `fastapi`, `uvicorn[standard]`, `pydantic-settings`, `sqlalchemy`, `alembic`, `httpx`, and `structlog`, plus test dependencies `pytest`, `pytest-asyncio`, `pytest-cov`, and `ruff`.

Run:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -e ".\backend[test]"
```

Expected: all packages install successfully and `python --version` reports Python 3.12.x.

- [ ] **Step 4: Run the tests to verify they fail for the missing application module**

Run: `.\.venv\Scripts\python -m pytest backend/tests/integration/api/test_health.py -v`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'shieldchain.main'`.

- [ ] **Step 5: Implement the minimal application factory and health router**

```python
# backend/src/shieldchain/api/health.py
from fastapi import APIRouter

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def readiness() -> dict[str, str]:
    return {"status": "ready"}
```

```python
# backend/src/shieldchain/main.py
from fastapi import FastAPI

from shieldchain.api.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI(title="ShieldChain API", version="0.1.0")
    app.include_router(health_router, prefix="/api/v1")
    return app


app = create_app()
```

- [ ] **Step 6: Add repository exclusions and safe environment examples**

`.gitignore` must exclude `.env`, `.venv/`, `node_modules/`, build output, caches, coverage, SQLite runtime files, logs and `.superpowers/`. `.env.example` must contain empty `DEEPSEEK_API_KEY=`, `DEEPSEEK_BASE_URL=https://api.deepseek.com`, `DEEPSEEK_MODEL=deepseek-chat`, and `DATABASE_URL=sqlite:///./data/shieldchain.db`.

- [ ] **Step 7: Run the focused and baseline checks**

Run:

```powershell
.\.venv\Scripts\python -m pytest backend/tests/integration/api/test_health.py -v
.\.venv\Scripts\python -m ruff check backend
```

Expected: 2 tests pass and Ruff exits with “All checks passed!”.

- [ ] **Step 8: Update the development log and commit**

Append the exact commands and results to `development-logs/2026-07-13.md` or the actual execution date log.

```powershell
git add .gitignore .env.example backend development-logs
git commit -m "chore: establish backend health foundation"
```

Expected: one commit containing only Task 1 files.

---

### Task 2: Typed Configuration, Request IDs, and Safe Error Responses

**Files:**
- Create: `backend/src/shieldchain/core/__init__.py`
- Create: `backend/src/shieldchain/core/config.py`
- Create: `backend/src/shieldchain/core/errors.py`
- Create: `backend/src/shieldchain/core/request_id.py`
- Modify: `backend/src/shieldchain/main.py`
- Create: `backend/tests/unit/core/test_config.py`
- Create: `backend/tests/integration/api/test_errors.py`

**Interfaces:**
- Produces: `Settings` with `environment`, `database_url`, `deepseek_base_url`, `deepseek_model`, `deepseek_api_key`
- Produces: `get_settings() -> Settings`
- Produces: `ApiError(code: str, message: str, status_code: int)`
- Produces: response header `X-Request-ID` and error body `{"error": {"code": str, "message": str, "request_id": str}}`

- [ ] **Step 1: Write failing configuration and error-contract tests**

```python
def test_settings_load_secret_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-secret")
    settings = Settings(_env_file=None)
    assert settings.deepseek_api_key.get_secret_value() == "test-secret"
    assert "test-secret" not in repr(settings)
```

```python
def test_unhandled_error_is_stable_and_does_not_leak_secret(client) -> None:
    response = client.get("/api/v1/test-only/error", headers={"X-Request-ID": "req-123"})
    assert response.status_code == 500
    assert response.headers["X-Request-ID"] == "req-123"
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "Internal server error",
            "request_id": "req-123",
        }
    }
    assert "test-secret" not in response.text
```

- [ ] **Step 2: Run focused tests and confirm missing symbols fail**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/core/test_config.py backend/tests/integration/api/test_errors.py -v`

Expected: FAIL because `Settings`, request middleware and exception handlers do not exist.

- [ ] **Step 3: Implement typed settings with secret-safe representation**

```python
from functools import lru_cache

from pydantic import AnyHttpUrl, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    environment: str = "development"
    database_url: str = "sqlite:///./data/shieldchain.db"
    deepseek_base_url: AnyHttpUrl = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_api_key: SecretStr = SecretStr("")


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 4: Implement request ID middleware and stable exception handlers**

Use the incoming `X-Request-ID` only when it matches `^[A-Za-z0-9._-]{1,64}$`; otherwise generate `uuid4().hex`. Store it on `request.state.request_id`, return it in every response header, and include it in JSON error bodies. The catch-all handler must return the fixed public message `Internal server error` without exception details.

- [ ] **Step 5: Run focused and full backend tests**

Run:

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/core/test_config.py backend/tests/integration/api/test_errors.py -v
.\.venv\Scripts\python -m pytest backend/tests -v
.\.venv\Scripts\python -m ruff check backend
```

Expected: all tests pass and Ruff reports no violations.

- [ ] **Step 6: Record verification and commit**

```powershell
git add backend development-logs
git commit -m "feat: add safe configuration and API error contracts"
```

---

### Task 3: Structured Logging with Mandatory Redaction

**Files:**
- Create: `backend/src/shieldchain/core/logging.py`
- Modify: `backend/src/shieldchain/core/request_id.py`
- Modify: `backend/src/shieldchain/main.py`
- Create: `backend/tests/unit/core/test_logging.py`

**Interfaces:**
- Produces: `configure_logging(environment: str) -> None`
- Produces: `redact_sensitive_fields(logger, method_name, event_dict) -> dict`
- Consumes: request ID stored by Task 2

- [ ] **Step 1: Write redaction tests before configuring Structlog**

```python
def test_redaction_removes_nested_secrets() -> None:
    event = {
        "authorization": "Bearer abc",
        "payload": {"api_key": "secret", "query": "safe"},
    }
    result = redact_sensitive_fields(None, "info", event)
    assert result["authorization"] == "[REDACTED]"
    assert result["payload"]["api_key"] == "[REDACTED]"
    assert result["payload"]["query"] == "safe"
```

- [ ] **Step 2: Run the test and verify the import fails**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/core/test_logging.py -v`

Expected: FAIL because `shieldchain.core.logging` does not exist.

- [ ] **Step 3: Implement recursive redaction and JSON logging**

Redact keys case-insensitively when they equal or contain `authorization`, `api_key`, `token`, `password`, `secret`, or `cookie`. Preserve values of non-sensitive keys. Configure JSON output outside tests and deterministic console output during tests. Bind `request_id` for request-scoped logs and clear context variables after the response.

- [ ] **Step 4: Verify secret values never appear in captured logs**

Add a test that logs an event containing `Bearer abc` and `test-secret`, captures output, and asserts both values are absent while `[REDACTED]` is present.

Run:

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/core/test_logging.py -v
.\.venv\Scripts\python -m pytest backend/tests -v
.\.venv\Scripts\python -m ruff check backend
```

Expected: all tests pass.

- [ ] **Step 5: Record verification and commit**

```powershell
git add backend development-logs
git commit -m "feat: add redacted structured logging"
```

---

### Task 4: SQLite Session Boundary and Readiness Check

**Files:**
- Create: `backend/src/shieldchain/db/__init__.py`
- Create: `backend/src/shieldchain/db/base.py`
- Create: `backend/src/shieldchain/db/session.py`
- Create: `backend/migrations/env.py`
- Create: `backend/migrations/script.py.mako`
- Create: `backend/migrations/versions/.gitkeep`
- Create: `backend/alembic.ini`
- Modify: `backend/src/shieldchain/api/health.py`
- Modify: `backend/src/shieldchain/main.py`
- Create: `backend/tests/unit/db/test_session.py`
- Modify: `backend/tests/integration/api/test_health.py`

**Interfaces:**
- Produces: `create_engine_from_url(database_url: str) -> Engine`
- Produces: `create_session_factory(engine: Engine) -> sessionmaker[Session]`
- Produces: `check_database(engine: Engine) -> bool`
- Readiness returns HTTP 503 with `{"status": "not_ready", "checks": {"database": "failed"}}` when `SELECT 1` fails

- [ ] **Step 1: Write tests for SQLite configuration and failed readiness**

```python
def test_sqlite_engine_accepts_cross_thread_test_client() -> None:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT 1").scalar_one() == 1
```

Add an API test overriding the database check to return `False` and assert readiness returns 503 with the exact body in the interface contract.

- [ ] **Step 2: Run focused tests and verify missing database modules fail**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/db/test_session.py backend/tests/integration/api/test_health.py -v`

Expected: FAIL because the database boundary is undefined.

- [ ] **Step 3: Implement engine, session factory and database check**

For SQLite URLs, set `connect_args={"check_same_thread": False}`. `check_database` executes `SELECT 1`, returns `True` on success, logs a sanitized error on `SQLAlchemyError`, and returns `False`. Do not expose the database URL in readiness responses.

- [ ] **Step 4: Configure Alembic to import `shieldchain.db.base.Base`**

Set `target_metadata = Base.metadata`; read the URL from `get_settings().database_url` rather than committing a machine-specific path. Verify configuration without generating a migration:

Run: `.\.venv\Scripts\alembic -c backend/alembic.ini current`

Expected: exit code 0 with no migration revision yet.

- [ ] **Step 5: Run database, API and full regression checks**

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/db/test_session.py backend/tests/integration/api/test_health.py -v
.\.venv\Scripts\python -m pytest backend/tests -v
.\.venv\Scripts\python -m ruff check backend
```

Expected: all tests pass.

- [ ] **Step 6: Record verification and commit**

```powershell
git add backend development-logs
git commit -m "feat: add sqlite persistence boundary"
```

---

### Task 5: DeepSeek Port and HTTP Adapter

**Files:**
- Create: `backend/src/shieldchain/llm/__init__.py`
- Create: `backend/src/shieldchain/llm/ports.py`
- Create: `backend/src/shieldchain/llm/deepseek.py`
- Create: `backend/tests/unit/llm/test_deepseek.py`
- Create: `backend/tests/integration/llm/test_deepseek_live.py`
- Modify: `.env.example`

**Interfaces:**
- Produces: immutable `ChatMessage(role: Literal["system", "user", "assistant"], content: str)`
- Produces: immutable `ChatRequest(messages: tuple[ChatMessage, ...], temperature: float = 0.0, max_tokens: int = 1024)`
- Produces: immutable `ChatResponse(content: str, model: str, prompt_tokens: int, completion_tokens: int)`
- Produces: `class LlmClient(Protocol): async def chat(self, request: ChatRequest) -> ChatResponse`
- Produces: `DeepSeekClient(settings: Settings, http_client: httpx.AsyncClient)`

- [ ] **Step 1: Write HTTP contract tests using HTTPX MockTransport**

Test that the adapter sends `POST {base_url}/chat/completions`, uses `Authorization: Bearer <key>`, sends the configured model and messages, and maps the response into `ChatResponse`. Add separate tests for 401, 429, timeout and malformed JSON.

```python
response = await client.chat(
    ChatRequest(messages=(ChatMessage(role="user", content="hello"),))
)
assert response.content == "world"
assert response.prompt_tokens == 3
assert response.completion_tokens == 1
```

- [ ] **Step 2: Run adapter tests and verify missing port fails**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/llm/test_deepseek.py -v`

Expected: FAIL because `ChatRequest` and `DeepSeekClient` are undefined.

- [ ] **Step 3: Implement immutable request/response types and the protocol**

Use frozen dataclasses for transport-independent types. Validate `temperature` between 0 and 2, `max_tokens` between 1 and 8192, non-empty messages, and non-empty message content before making HTTP requests.

- [ ] **Step 4: Implement the DeepSeek adapter with bounded behavior**

Set a 30-second total timeout, no automatic retry for 401/403, and at most two retries for 429/5xx/timeouts using delays of 0.5 and 1.0 seconds. Raise typed `LlmAuthenticationError`, `LlmRateLimitError`, `LlmUnavailableError`, or `LlmResponseError`. Log model, latency, attempt and token counts, never prompts, authorization headers or key values.

- [ ] **Step 5: Add an opt-in live smoke test**

The test must skip unless `RUN_LIVE_DEEPSEEK_TEST=1` and a non-empty key are present. It sends only `Reply with OK` and asserts non-empty content. Default test execution must report it as skipped and make no network request.

- [ ] **Step 6: Run offline tests, then optionally run the paid smoke test**

Run offline:

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/llm/test_deepseek.py -v
.\.venv\Scripts\python -m pytest backend/tests -v
.\.venv\Scripts\python -m ruff check backend
```

Expected: unit tests pass; live test is skipped.

Optional only with explicit user approval and configured key:

```powershell
$env:RUN_LIVE_DEEPSEEK_TEST='1'
.\.venv\Scripts\python -m pytest backend/tests/integration/llm/test_deepseek_live.py -v
```

Expected: one live test passes with one minimal API call.

- [ ] **Step 7: Record verification and commit**

```powershell
git add .env.example backend development-logs
git commit -m "feat: add bounded DeepSeek adapter"
```

---

### Task 6: React Application Shell and Backend Health Indicator

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/tsconfig.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/eslint.config.js`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/app/App.tsx`
- Create: `frontend/src/app/router.tsx`
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/features/dashboard/DashboardPage.tsx`
- Create: `frontend/src/styles/tokens.css`
- Create: `frontend/src/test/setup.ts`
- Create: `frontend/src/app/App.test.tsx`
- Create: `frontend/src/api/client.test.ts`

**Interfaces:**
- Produces: `getLiveness(signal?: AbortSignal) -> Promise<{status: "ok"}>`
- Produces: application routes `/` and `/events`
- Consumes: backend `/api/v1/health/live`

- [ ] **Step 1: Create package metadata and install locked dependencies**

Use React, React DOM and React Router as runtime dependencies; Vite, TypeScript, Vitest, jsdom, Testing Library, ESLint and the React ESLint plugins as development dependencies.

Run: `npm install --prefix frontend`

Expected: `frontend/package-lock.json` is created and installation exits 0.

- [ ] **Step 2: Write failing UI and API client tests**

```tsx
it('shows the ShieldChain navigation and healthy backend state', async () => {
  render(<App />)
  expect(screen.getByText('盾链智御')).toBeInTheDocument()
  expect(await screen.findByText('系统运行正常')).toBeInTheDocument()
})
```

```ts
it('maps liveness response', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    new Response(JSON.stringify({status: 'ok'}), {status: 200})
  ))
  await expect(getLiveness()).resolves.toEqual({status: 'ok'})
})
```

- [ ] **Step 3: Run tests and verify missing components fail**

Run: `npm test --prefix frontend -- --run`

Expected: FAIL because `App` and `getLiveness` do not exist.

- [ ] **Step 4: Implement the typed client and accessible application shell**

The client must use a 5-second `AbortController` timeout, reject non-2xx responses, validate `status === "ok"`, and expose no secrets. The shell provides visible navigation labels for 运营总览、事件调查、智能体工作台、知识库、处置中心、报告与审计. Only 运营总览 is functional in this phase; other destinations render a clear “尚未进入该开发阶段” message rather than fake functionality.

- [ ] **Step 5: Implement theme tokens and responsive layout**

Define semantic CSS variables for background, surface, primary pale blue, foreground, muted, border, warning and danger. Ensure keyboard focus remains visible, status is expressed with text plus color, and the navigation stacks below 680px.

- [ ] **Step 6: Run frontend tests, lint, typecheck and production build**

```powershell
npm test --prefix frontend -- --run
npm run lint --prefix frontend
npm run typecheck --prefix frontend
npm run build --prefix frontend
```

Expected: tests pass, lint and typecheck exit 0, and Vite creates `frontend/dist`.

- [ ] **Step 7: Record verification and commit**

```powershell
git add frontend development-logs
git commit -m "feat: add security operations application shell"
```

---

### Task 7: Windows Developer Commands and Phase Gate

**Files:**
- Create: `scripts/dev.ps1`
- Create: `scripts/test.ps1`
- Create: `scripts/verify.ps1`
- Create: `README.md`
- Modify: `docs/operations/local-development.md`
- Modify: `docs/plans/development-roadmap.md`
- Modify: `development-logs/YYYY-MM-DD.md`

**Interfaces:**
- Produces: `powershell -ExecutionPolicy Bypass -File scripts/dev.ps1`
- Produces: `powershell -ExecutionPolicy Bypass -File scripts/test.ps1`
- Produces: `powershell -ExecutionPolicy Bypass -File scripts/verify.ps1`

- [ ] **Step 1: Write a PowerShell contract test for missing prerequisites**

Create a Pester-free test invocation by adding `-CheckOnly` to `dev.ps1`. It must print actionable errors and exit 1 when `.venv/Scripts/python.exe`, `frontend/node_modules`, or `.env` are missing; it must never print values from `.env`.

Run before implementation: `powershell -ExecutionPolicy Bypass -File scripts/dev.ps1 -CheckOnly`

Expected: FAIL because `scripts/dev.ps1` does not exist.

- [ ] **Step 2: Implement safe development startup**

`dev.ps1` validates prerequisites, starts Uvicorn on `127.0.0.1:8000` and Vite on `127.0.0.1:5173` as child processes, stops both on Ctrl+C, and returns a non-zero exit code when either child exits unexpectedly. It must not use `Invoke-Expression` or construct commands from untrusted strings.

- [ ] **Step 3: Implement default test and full verification scripts**

`test.ps1` runs backend Pytest and frontend Vitest without live cloud flags. `verify.ps1` runs Ruff, Pytest, ESLint, TypeScript checking, Vitest and the production frontend build in that order, stopping at the first failure and returning its exit code.

- [ ] **Step 4: Replace local-development prose with exact setup and run commands**

Document Python 3.12, Node installation prerequisite, venv creation, dependency installation, copying `.env.example` to `.env`, startup, default tests, full verification, optional live DeepSeek test and troubleshooting. State clearly that `.env` must never be committed.

- [ ] **Step 5: Run the complete Phase 1 verification from a clean shell**

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test.ps1
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
git status --short
```

Expected: all checks exit 0. `git status --short` lists only the current task's intended documentation and scripts before commit; it must not list `.env`, `.venv`, SQLite data, logs or build artifacts.

- [ ] **Step 6: Perform secret and scope scans**

```powershell
rg -n "sk-[A-Za-z0-9]{16,}|Bearer [A-Za-z0-9._-]{16,}|DEEPSEEK_API_KEY=.+" . -g '!*.pdf' -g '!frontend/package-lock.json'
rg -n "Milvus|BM25|Reranker|multi-agent|tool gateway" backend/src frontend/src
```

Expected: the secret scan returns no matches containing real values. The scope scan returns no implementation of future subsystems; documentation text and interface names are acceptable only outside product source.

- [ ] **Step 7: Update the phase gate and development log**

Mark Phase 1 complete in `docs/plans/development-roadmap.md` only when all verification commands pass. Record versions, commands, test counts, skipped live tests, known limitations and the next phase goal in the actual date log.

- [ ] **Step 8: Commit the verified phase gate**

```powershell
git add README.md scripts docs development-logs
git commit -m "docs: complete phase one engineering gate"
git status --short
```

Expected: commit succeeds and the final status is clean.

---

## Phase 1 Exit Review

Phase 1 is accepted only when all statements below have fresh evidence:

- Windows can start the backend and frontend without Docker.
- Both health endpoints satisfy their exact contracts; readiness becomes 503 when SQLite is unavailable.
- Settings never expose `DEEPSEEK_API_KEY` in representations, errors or logs.
- Every response includes a valid request ID and errors have a stable public schema.
- Structured logs redact nested secrets.
- SQLite and Alembic boundaries work without introducing business models early.
- DeepSeek is accessible only through `LlmClient`; offline tests cover success, authentication, rate limit, timeout and malformed response.
- Default tests perform no paid network requests.
- The frontend shell is responsive, accessible and displays backend health without pretending future modules are complete.
- `scripts/verify.ps1` passes and the repository contains no runtime secrets or generated artifacts.
- Documentation and the execution-date development log reflect verified reality.

After acceptance, write a separate detailed plan for Phase 2: deterministic simulated incident loop. Do not implement Phase 2 from this plan.

