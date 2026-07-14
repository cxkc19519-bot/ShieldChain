# Windows 本地开发

阶段 2 在 Windows 上直接运行 FastAPI 后端和 React 前端，不要求 Docker。本阶段只是使用固定钓鱼场景、SQLite 和模拟防火墙的确定性仿真，不是真实保护设备，也不会连接真实 SIEM、EDR、防火墙或终端。本地不运行大模型或 Milvus；默认测试不会访问 DeepSeek。

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

`npm ci` 必须使用已提交的 `frontend/package-lock.json`。`.env` 绝不能提交、复制到日志或在终端中输出。

## 3. 环境变量

`.env.example` 只提供安全模板：

- `DEEPSEEK_API_KEY`：真实 DeepSeek API 密钥；离线开发时必须留空。
- `DEEPSEEK_BASE_URL`：DeepSeek API 基础地址。
- `DEEPSEEK_MODEL`：请求的模型名称。
- `RUN_LIVE_DEEPSEEK_TEST`：付费实时冒烟测试开关；默认必须为 `0`。
- `DATABASE_URL`：本地 SQLite 连接地址。

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

## 6. 离线测试、阶段 smoke 与完整验证

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase2-smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

`test.ps1` 依次运行后端 Pytest 和前端 Vitest。独立 smoke 使用仓库已有 `.venv` 和 `frontend\node_modules`，在系统临时目录创建唯一 SQLite 和日志，运行 Alembic，启动真实后端及带 `--strictPort` 的 Vite，并只经 5173 执行 readiness/reset/start/poll/incident/audit；轮询使用 30 秒单调截止时间。`verify.ps1` 严格按 Ruff、Pytest、ESLint、TypeScript、Vitest、前端生产构建、阶段 2 smoke 的顺序执行，并在首个失败处停止且返回该退出码。脚本会移除继承的 `RUN_LIVE_DEEPSEEK_TEST`，因此不会意外产生付费调用。

smoke 完全不命名、读取、检查、创建、覆盖或删除仓库 `.env`。Alembic 和 FastAPI 后端都从唯一的系统临时工作目录启动，仅使用绝对仓库路径与子进程环境覆盖；Vite 继续从 `frontend` 工作目录启动。脚本会恢复调用者环境、停止仅由自己统一跟踪的 PID、删除自己的临时目录，并确认 8000/5173 不再监听。

## 7. 可选实时 DeepSeek 冒烟测试

只有获得明确批准并确认费用后，才可以在当前 PowerShell 会话中显式设置真实密钥并单独运行实时测试：

```powershell
$env:DEEPSEEK_API_KEY = "<从安全密钥存储读取>"
$env:RUN_LIVE_DEEPSEEK_TEST = "1"
.\.venv\Scripts\python.exe -m pytest backend\tests\integration\llm\test_deepseek_live.py -v
Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST
Remove-Item Env:\DEEPSEEK_API_KEY
```

不得把真实密钥写进 `.env.example`、命令历史、截图、日志或测试报告。本阶段验收不要求运行此付费测试。

## 8. 故障排查

- 缺少 `.venv\Scripts\python.exe`：重新创建虚拟环境并安装 `backend[test]`。
- 缺少 `frontend\node_modules`：运行 `npm ci --prefix frontend`，不要使用未锁定的安装方式。
- 缺少 `.env`：运行 `Copy-Item .env.example .env`，不要打印文件内容。
- `npm.cmd` 不可用：安装当前 Node.js LTS 后重新打开 PowerShell。
- 端口被占用：smoke 会安全失败且绝不会停止未知 owner。确认该进程属于自己后手工关闭，再重试；不要用宽泛的进程清理命令。
- Alembic 迁移失败：确认 `DATABASE_URL` 使用可写的 SQLite 路径，并单独运行 `upgrade head` 查看迁移错误；smoke 仍会执行清理。
- 后端或 Vite 启动失败：检查 smoke 输出中的阶段和退出码；脚本只在系统临时目录保留运行期日志，并在结束时删除整个自有目录。
- 就绪检查返回 503：检查 `DATABASE_URL` 指向的目录是否可写且已经迁移到 head。
- 调查未在 30 秒内结束或返回畸形数据：smoke 会非零退出、停止自有进程、删除自有文件并检查端口；修复根因后重新运行完整命令。

当前持久化只支持本机 SQLite，启动和 smoke 只面向单机开发；这不是并发生产数据库或部署方案。Docker 不是阶段 2 本地开发的前置条件，阶段 3 RAG 也尚未实现。
