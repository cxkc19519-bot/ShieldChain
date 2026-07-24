# Windows 本地开发

阶段 3 继续在 Windows 上直接运行 FastAPI 后端和 React 前端，不要求 Docker。仓库包含阶段 2 的确定性钓鱼事件闭环，以及阶段 3 的文档解析、分块、索引、混合检索、重排、引用、拒答、评测核心和知识库页面。当前默认应用没有接通 DeepSeek、BGE-M3 Embedding、托管 Milvus 或 BGE-Reranker-v2-m3 的真实服务；知识 API 因此默认失败关闭并返回 `503 knowledge_service_unconfigured`，不会伪造云链路成功。

## 1. 检查工具版本

必须安装 Python `>=3.12,<3.15` 和带有 npm 的 Node.js。打开新的 PowerShell 后检查：

```powershell
py -3.12 --version
node --version
npm.cmd --version
```

## 2. 创建环境并锁定安装依赖

从仓库根目录运行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".\backend[test]"
npm ci --prefix frontend
Copy-Item .env.example .env
```

`npm ci` 必须使用已提交的 `frontend/package-lock.json`。后端依赖已经包含上传表单所需的 `python-multipart`，执行 `pip install -e ".\backend[test]"` 会自动安装，不需要另行执行未锁定的安装命令。`.env` 绝不能提交、复制到日志或在终端中输出。

## 3. 环境变量

`.env.example` 只提供安全模板：

- `DEEPSEEK_API_KEY`：真实 DeepSeek API 密钥；离线开发时必须留空。
- `DEEPSEEK_BASE_URL`：DeepSeek API 基础地址。
- `DEEPSEEK_MODEL`：请求的模型名称。
- `RUN_LIVE_DEEPSEEK_TEST`：付费实时冒烟测试开关；默认必须为 `0`。
- `DATABASE_URL`：本地 SQLite 连接地址。

Embedding、Milvus 和 Reranker 的实时连接变量尚未进入默认应用配置。`verify.ps1 -LiveProfile` 预留检查以下进程环境变量，但不会读取或输出变量值：`RAG_EMBEDDING_BASE_URL`、`RAG_EMBEDDING_API_KEY`、`RAG_EMBEDDING_MODEL`、`MILVUS_URI`、`MILVUS_TOKEN`、`MILVUS_COLLECTION`、`RAG_RERANKER_BASE_URL`、`RAG_RERANKER_API_KEY`、`RAG_RERANKER_MODEL`。这些名称是阶段 3 门禁的配置合同，不代表真实适配器已经在默认应用中启用。

## 4. 启动开发服务

首次启动或迁移版本变化后，先在仓库根目录升级本地数据库：

```powershell
$env:DATABASE_URL = "sqlite:///./data/shieldchain.db"
.\.venv\Scripts\python.exe -m alembic -c backend\alembic.ini upgrade head
```

如需验证迁移可逆性，可在专用的临时 SQLite 上运行 `downgrade base`，再运行 `upgrade head`；不要对需要保留的本地数据库做降级测试。

先检查三个本地前置项：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1 -CheckOnly
```

然后同时启动服务：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
```

- 后端：`http://127.0.0.1:8000`
- 前端：`http://127.0.0.1:5173`
- 存活检查：`http://127.0.0.1:8000/api/v1/health/live`
- 就绪检查：`http://127.0.0.1:8000/api/v1/health/ready`
- 知识库页面：`http://127.0.0.1:5173/knowledge`

按 Ctrl+C 时脚本会停止两个子进程。如果任何子进程意外退出，脚本会返回非零状态。

## 5. 阶段 2 调查闭环

浏览器调查页和 API 都执行相同流程：重置固定钓鱼场景，启动调查，轮询至终态，然后读取事件和有序审计。手工调用也应始终通过 Vite 来源 `http://127.0.0.1:5173/api/v1`，以覆盖真实代理路径：

```powershell
$root = "http://127.0.0.1:5173/api/v1"
$reset = Invoke-RestMethod -Method Post -Uri "$root/simulations/phishing/reset" -ContentType "application/json" -Body "{}"
$body = @{ simulation_instance_id = $reset.simulation.id; mode = "normal" } | ConvertTo-Json
$run = Invoke-RestMethod -Method Post -Uri "$root/investigations" -ContentType "application/json" -Body $body
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    $final = Invoke-RestMethod -Uri "$root/investigations/$($run.run_id)"
    if ($final.status -notin @("closed", "needs_review", "failed", "interrupted")) {
        Start-Sleep -Milliseconds 500
    }
} while ($final.status -notin @("closed", "needs_review", "failed", "interrupted") -and [DateTime]::UtcNow -lt $deadline)
$incident = Invoke-RestMethod -Uri "$root/incidents/$($run.incident_id)"
$audit = Invoke-RestMethod -Uri "$root/incidents/$($run.incident_id)/audit"
```

`normal` 模式应依次收集固定证据、规则研判、模拟封禁和验证，最终达到 `closed`，连接和防火墙状态均为 `blocked`。开发环境还支持 `fail_block_once` 故障注入：它应达到 `failed`，保留活动连接且不得报告成功；该模式用于验证失败语义，不属于正常 smoke。生产环境明确拒绝 `fail_block_once`。

## 6. 阶段 3/4/5/6/7 离线 smoke 与完整验证

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase2-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase3-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase4-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase5-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase6-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase7-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase8-baseline.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

`test.ps1` 依次运行后端 Pytest 和前端 Vitest。阶段 2 smoke 使用真实本地后端和 Vite 验证调查闭环。阶段 3 smoke 使用临时 SQLite、临时内容目录和确定性离线云替身验证完整 RAG 链路。阶段 4 smoke 验证离线多智能体状态机、原子输出/交接/审计和只读轨迹。阶段 5 smoke 验证可信工具成功闭环、审批拒绝、同键冲突、未知结果、紧急停止和编排恢复。阶段 6 smoke 验证失败重规划后经可信网关成功、未知结果只查询、循环/预算停止、审批拒绝、人工接管和安全轨迹；全部路径不联网、不执行 Shell、不访问真实设备，也不宣称真实模型自主规划已验证。

`verify.ps1` 严格按以下顺序执行，并在首个失败处停止且返回原退出码：

1. 后端 Ruff 和完整 Pytest（包含安全回归）；
2. 前端 ESLint、TypeScript、Vitest 和生产构建；
3. 临时 SQLite 上 Alembic `upgrade head` → `downgrade base` → `upgrade head`；
4. 固定双语 RAG 评测测试；
5. PowerShell 脚本契约；
6. 阶段 3、阶段 4、阶段 5、阶段 6 与阶段 7 离线 smoke。

验证脚本支持仓库路径包含空格。迁移数据库及阶段 3/4/5/6 smoke 数据均位于各自的系统临时目录并在退出时删除。完整 `verify.ps1` 与 smoke 会暂时移除全部四个已知实时测试开关，结束后恢复调用者环境，所以不会意外产生 DeepSeek、Embedding、Milvus 或 Reranker 云调用，也不会调用真实安全设备或真实模型规划器。
Phase 8 基线脚本使用 3 次预热和每场景 25 个样本，输出毫秒级 p50/p95 并按机器可读预算失败关闭。当前只测量进程内 liveness HTTP 与固定 RAG 数据集加载；完整结果和限制见 `docs/reports/phase8-baseline.md`。


阶段 2 smoke 完全不命名、读取、检查、创建、覆盖或删除仓库 `.env`。Alembic 和 FastAPI 后端都从唯一的系统临时工作目录启动，仅使用绝对仓库路径与子进程环境覆盖；Vite 继续从 `frontend` 工作目录启动。脚本会恢复调用者环境、停止仅由自己统一跟踪的 PID、删除自己的临时目录，并确认 8000/5173 不再监听。

## 7. 可选 live profile 配置检查

当前尚未获得 DeepSeek、Embedding、Milvus 和 Reranker 实时环境的授权，阶段 3 也没有完成真实云链路验收。需要在安全环境中检查未来 live 配置时，可先把上一节列出的变量通过进程环境或密钥服务注入，再运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1 -LiveProfile -LiveCallLimit 1
```

`-LiveCallLimit` 只接受 `0..10`，用于明确未来实时测试的调用上限；当前脚本无论该值是多少都只验证变量是否存在，实际云调用次数始终为 0，并输出 `REAL_CLOUD_PATHS_TESTED=False`。缺失配置时脚本返回 `2`，且只报告变量名，不输出密钥或地址。这个 profile 通过不能作为 DeepSeek、Embedding、Milvus 或 Reranker 云验收证明。

## 8. 单独的 DeepSeek 实时测试（当前不属于验收）

只有获得明确批准并确认费用后，才可以在当前 PowerShell 会话中显式设置真实密钥并单独运行实时测试：

```powershell
$env:DEEPSEEK_API_KEY = "<从安全密钥存储读取>"
$env:RUN_LIVE_DEEPSEEK_TEST = "1"
.\.venv\Scripts\python.exe -m pytest backend\tests\integration\llm\test_deepseek_live.py -v
Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST
Remove-Item Env:\DEEPSEEK_API_KEY
```

不得把真实密钥写进 `.env.example`、命令历史、截图、日志或测试报告。本阶段验收不要求运行此付费测试。

## 9. 故障排查

- 缺少 `.venv\Scripts\python.exe`：重新创建虚拟环境并安装 `backend[test]`。
- 缺少 `frontend\node_modules`：运行 `npm ci --prefix frontend`，不要使用未锁定的安装方式。
- 缺少 `.env`：运行 `Copy-Item .env.example .env`，不要打印文件内容。
- `npm.cmd` 不可用：安装当前 Node.js LTS 后重新打开 PowerShell。
- 端口被占用：smoke 会安全失败且绝不会停止未知 owner。确认该进程属于自己后手工关闭，再重试；不要用宽泛的进程清理命令。
- Alembic 迁移失败：确认 `DATABASE_URL` 使用可写的 SQLite 路径，并单独运行 `upgrade head` 查看迁移错误；smoke 仍会执行清理。
- 上传接口提示 multipart 解析不可用：重新执行 `.\.venv\Scripts\python.exe -m pip install -e ".\backend[test]"`；该命令会自动安装声明的 `python-multipart`。
- 后端或 Vite 启动失败：检查 smoke 输出中的阶段和退出码；脚本只在系统临时目录保留运行期日志，并在结束时删除整个自有目录。
- 就绪检查返回 503：检查 `DATABASE_URL` 指向的目录是否可写且已经迁移到 head。

## 10. HTTP 安全与生产 profile

开发默认只信任 `127.0.0.1`、`localhost` 和测试客户端 Host，并只允许本地 Vite 来源。可通过 JSON 数组形式的 `HTTP_ALLOWED_HOSTS` 与 `HTTP_ALLOWED_ORIGINS` 覆盖；`HTTP_MAX_REQUEST_BYTES` 控制所有声明了 `Content-Length` 的请求上限，知识上传仍受更小的专用解析与展开预算约束。

生产 profile 示例：

```powershell
$env:ENVIRONMENT = "production"
$env:HTTP_ALLOWED_HOSTS = '["shieldchain.example.internal"]'
$env:HTTP_ALLOWED_ORIGINS = '["https://shieldchain.example.internal"]'
```

生产环境拒绝 Host/Origin 通配符。API 响应统一包含 `no-store`、CSP、Permissions-Policy、Referrer-Policy、`nosniff` 和防嵌入头；生产 profile 额外发送 HSTS。CORS 不携带凭据，只允许 `GET`、`POST`、`DELETE` 和 `Content-Type`/`X-Request-ID`，并仅向允许来源暴露请求 ID。

请求体超过全局上限返回稳定的 `413 request_too_large`，无效 `Content-Length` 返回 `400 invalid_content_length`；响应不回显输入值。上传接口继续要求 `Content-Length`，并对 multipart 字段数、单文件大小、扩展名、媒体类型、文件名和解压资源预算分别失败关闭。

历史 `test` 会归一化为 `testing`，环境名称忽略大小写；除此之外只接受 `development`、`testing` 和 `production`。
- 调查未在 30 秒内结束或返回畸形数据：smoke 会非零退出、停止自有进程、删除自有文件并检查端口；修复根因后重新运行完整命令。

当前持久化只支持本机 SQLite，启动和 smoke 只面向单机开发；这不是并发生产数据库或部署方案。Docker 不是阶段 7 本地开发的前置条件。真实云/安全设备适配器、真实模型自主规划、授权环境验证和 Docker Compose 部署仍是后续工作。

## 11. 存活、就绪、版本与关闭

三个公开运维端点职责不同：

- `/api/v1/health/live` 只证明进程可以响应，不访问数据库。
- `/api/v1/health/ready` 同时检查数据库连接、Alembic 必须精确位于 `20260724_01`，以及应用仍在接受请求；任一失败返回 503。
- `/api/v1/health/version` 只返回服务名、安装包版本和期望 schema revision，不暴露主机名、用户名、路径、Git ref 或配置。

全新 checkout 首次启动会创建 SQLite 文件，但在执行迁移前 readiness 必须保持 `not_ready/migrations=unavailable`：

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m alembic upgrade head
```

应用 lifespan 在恢复中断运行后才标记 `accepting`；关闭开始时先切换为 `stopping`，再调用后台运行器的有界关闭。运行器停止接收新任务，等待配置的 1–30 秒超时，取消仍未完成的 asyncio 包装任务，并依赖下次启动恢复已经进入线程的短工作流。

结构化日志只保留 request ID、方法、公开路径、状态、耗时和错误类型。tenant/principal/actor 标识、凭据、Cookie、提示、推理轨迹、原始 payload 与证据 payload 均在处理器中替换为 `[REDACTED]`。
