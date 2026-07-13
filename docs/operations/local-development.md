# Windows 本地开发

阶段 1 在 Windows 上直接运行 FastAPI 后端和 React 前端，不要求 Docker。本地不运行大模型或 Milvus；默认测试也不会访问 DeepSeek。

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

## 5. 离线测试与完整验证

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

`test.ps1` 依次运行后端 Pytest 和前端 Vitest。`verify.ps1` 严格按 Ruff、Pytest、ESLint、TypeScript、Vitest、前端生产构建的顺序执行，并在首个失败处停止。两个脚本都会移除继承的 `RUN_LIVE_DEEPSEEK_TEST`，因此不会意外产生付费调用。

## 6. 可选实时 DeepSeek 冒烟测试

只有获得明确批准并确认费用后，才可以在当前 PowerShell 会话中显式设置真实密钥并单独运行实时测试：

```powershell
$env:DEEPSEEK_API_KEY = "<从安全密钥存储读取>"
$env:RUN_LIVE_DEEPSEEK_TEST = "1"
.\.venv\Scripts\python.exe -m pytest backend\tests\integration\llm\test_deepseek_live.py -v
Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST
Remove-Item Env:\DEEPSEEK_API_KEY
```

不得把真实密钥写进 `.env.example`、命令历史、截图、日志或测试报告。本阶段验收不要求运行此付费测试。

## 7. 故障排查

- 缺少 `.venv\Scripts\python.exe`：重新创建虚拟环境并安装 `backend[test]`。
- 缺少 `frontend\node_modules`：运行 `npm ci --prefix frontend`，不要使用未锁定的安装方式。
- 缺少 `.env`：运行 `Copy-Item .env.example .env`，不要打印文件内容。
- `npm.cmd` 不可用：安装当前 Node.js LTS 后重新打开 PowerShell。
- 端口被占用：停止占用 `127.0.0.1:8000` 或 `127.0.0.1:5173` 的本地进程后重试。
- 就绪检查返回 503：检查 `DATABASE_URL` 指向的目录是否可写。

Docker 不是阶段 1 本地开发的前置条件。
