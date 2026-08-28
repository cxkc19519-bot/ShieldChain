# Windows 本地开发与运行

> 文档状态：当前参考（更新于 2026-08-08）。固定钓鱼仿真接口已退役，验证以真实告警、运营报告、RAG 和助手为主。

## 1. 环境

- Windows PowerShell 5.1 或 PowerShell 7；
- Conda 环境 `ShieldChain`，Python `>=3.12,<3.15`；
- Node.js LTS 和 npm；
- 可选 Docker Desktop；
- 可选本地 Milvus、Embedding 和 Reranker 服务。

```powershell
conda activate ShieldChain
python -m pip install -e ".\backend[test]"
npm ci --prefix frontend
Copy-Item .env.example .env
```

`.env` 不得提交。至少检查以下变量：

- `DATABASE_URL`：应用元数据数据库；
- `RAG_CONTENT_ROOT`：知识库持久化目录；
- `ASSISTANT_DATA_ROOT`：助手会话和记忆目录；
- `WAZUH_WEBHOOK_TOKEN`：Wazuh 转发鉴权；
- `DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL`、`DEEPSEEK_API_KEY`：OpenAI 兼容模型接口；使用本地 vLLM 时由 Compose 覆盖。

## 2. 一键启动

```powershell
python app.py
```

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`
- API 文档：`http://127.0.0.1:8000/docs`

关闭窗口或按脚本提示停止进程。运行数据保存在配置目录中，重新启动后知识库和助手会话仍存在。

## 3. 分别启动

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
```

也可在两个终端分别运行后端和前端：

```powershell
conda run -n ShieldChain uvicorn shieldchain.main:app --app-dir backend/src --host 127.0.0.1 --port 8000
npm --prefix frontend run dev -- --host 127.0.0.1 --port 5173
```

## 4. 模型配置

### 外部 API

在 `.env` 中配置 OpenAI 兼容基础地址、模型名和 API Key。密钥只通过环境或密钥服务注入，不写入测试夹具或日志。

### 本地 vLLM

本地模型由服务器 Docker 覆盖配置提供，业务代码仍使用相同的 OpenAI 兼容客户端。不要同时让多个服务争用同一组 GPU。

## 5. RAG

上传文档后检查：

1. 文档版本状态为成功；
2. 分块状态明确显示 LLM 成功或规则降级原因；
3. “查看分块”显示合理偏移与长度；
4. 混合检索返回来源、块号和分数；
5. 重启应用后知识库仍存在。

Milvus 或模型不可用时，界面必须显示真实降级状态，不能写成云 RAG 成功。

## 6. Wazuh 与运营报告

Wazuh 适配器配置见 [Wazuh 只读告警接入](wazuh-read-only-ingestion.md)。接收告警后可在“实时告警”查看，再由安全运营报告智能体按时间范围调用只读工具生成报告。

报告生成不会执行隔离、封禁或账户变更。真实处置必须进入独立审批和可信工具流程。

## 7. 验证

### 标准开发脚本

`scripts/dev.ps1`（开发启动）和 `scripts/test.ps1`（前后端测试）使用仓库根目录的 `.venv`，与上面的 Conda + `app.py` 启动方式是两种选择。若使用这些脚本，在仓库根目录配置：

```powershell
python -m venv .venv
Push-Location backend
& ..\.venv\Scripts\python.exe -m pip install -r requirements.lock
Pop-Location
npm ci --prefix frontend
# 首次配置时复制 .env.example；已有 .env 不要覆盖。
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev.ps1 -CheckOnly
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify.ps1
```

`scripts/verify.ps1` 是完整离线门禁，依次检查后端、前端、依赖审计、临时库迁移、脚本合同和 Task 14 smoke。它也支持 `backend/.venv` 或 PATH 中已装好锁定依赖的 Python（例如 CI）；不会自动开启付费模型调用。正常运行前端需要 Node.js/npm 在 PATH 中。Windows CI 使用 `scripts/verify.ps1 -StaticOnly`，该参数只将容器 smoke 限制为静态合同，其他门禁照常执行；Linux CI 独立实际构建和运行容器，避免 Windows 容器引擎误拉 Linux 镜像。

### 聚焦功能验证

```powershell
conda run -n ShieldChain python -m pytest `
  backend/tests/integration/api/test_operations_report.py `
  backend/tests/integration/api/test_wazuh_ingestion.py `
  backend/tests/unit/operations/test_operations_report_service.py `
  backend/tests/unit/rag/test_local_semantic_chunking.py -q

npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
```

Docker 配置检查：

```powershell
docker compose -f compose.yaml -f compose.server.yaml config --quiet
docker compose -f compose.yaml -f compose.local-llm.yaml config --quiet
```

旧阶段 smoke 中仍可能描述已退役的固定仿真；它们属于历史合同，不应作为当前真实数据链路的验收依据。

## 8. 数据与安全

- 不提交 `.env`、`backend/data/`、数据库、模型缓存或真实告警；
- 删除知识库、报告或会话前确认目标，并同步清理关联索引；
- 不在日志中输出 API Key、Webhook Token、原始工具结果或模型私有上下文；
- 服务器操作仅限 `/home/user/jhk`，不得读取或修改其他用户目录与进程。
