# ShieldChain

ShieldChain 是面向安全运营场景的多智能体分析系统。系统接收 Wazuh 等安全平台转发的真实告警，结合本地知识库、历史调查报告和受授权的只读工具，由专业智能体完成检索、研判、协作和安全运营报告生成。

项目默认坚持“分析与处置分离”：模型可以规划、选择工具和生成建议，但不能绕过确定性安全规则、审批、可信工具网关和执行后验证边界。

## 主要功能

- **真实告警接入**：接收、持久化并展示 Wazuh 高风险告警，支持人工复核和关联分析。
- **安全多智能体协作**：专业角色通过 ReAct 循环自主观察、选择工具、分析结果和交接任务。
- **安全运营报告智能体**：校验时间参数，自主选择事件、告警、漏洞、弱密码四类只读 MCP 工具，生成结构化建议、Markdown 和 HTML 预览。
- **RAG 知识库**：支持文档持久化、语义分块、混合检索、向量检索、重排、版本管理和分块查看。
- **智能助手**：结合知识库与历史调查报告回答问题，对话和本地记忆持久化保存。
- **本地模型部署**：提供 vLLM OpenAI 兼容服务配置，可使用 `Qwen3-30B-A3B-Instruct-2507-FP8` 替代外部 DeepSeek API。
- **安全边界**：只向前端公开受控轨迹和可验证结论，不公开私有提示词、思维链、原始凭据或敏感工具结果。

## 智能体团队

ShieldChain 当前启用 7 个专业智能体。它们不是按固定顺序依次运行：总控智能体通过 ReAct 循环观察当前公开状态，再根据任务、证据缺口、剩余预算和可用工具选择下一位专业智能体。

| 智能体 | 主要作用 | 典型输出 |
| --- | --- | --- |
| **总控智能体** | 理解任务目标和当前事实，选择下一位专业智能体，管理交接、循环预算和结束条件。 | 选择原因、当前风险焦点、交接摘要。 |
| **告警分诊智能体** | 对事件和告警进行分级、去重和优先级排序，识别需要优先人工处理的对象。 | 告警优先级、分诊依据、待处理清单。 |
| **威胁研判智能体** | 关联告警、漏洞、资产和攻击迹象，区分已确认事实、可疑线索与仍需补证的判断。 | 风险判断、攻击线索、证据缺口。 |
| **知识检索智能体** | 在需要外部依据时自主调用 RAG，检索行业规范、ATT&CK 技战术、漏洞知识和处置手册。 | 带来源的知识摘要、相关依据。 |
| **响应规划智能体** | 根据风险和证据提出处置建议，并说明执行前置条件和潜在影响；当前只规划，不直接执行高风险动作。 | 处置建议、前置条件、风险提示。 |
| **验证智能体** | 定义建议实施后应重新检查的日志、指标、资产状态和验收条件，不把“建议验证”写成“已经验证”。 | 验证清单、成功条件、失败判据。 |
| **报告智能体** | 汇总已确认事实、证据局限、风险结论、建议和引用，形成面向人工复核的中文报告。 | 调查摘要、研判结论、运营报告。 |

### 安全运营报告智能体

安全运营报告智能体是上述团队的任务入口和结果呈现层，负责：

1. 生成并校验查询时间范围；
2. 根据任务自主选择事件、告警、漏洞、弱密码四类只读 MCP 工具，不要求每次全部调用；
3. 分析工具返回结果，并将受控观察交给 ReAct 智能体团队；
4. 综合多角色结论，输出建议和限制条件；
5. 完成中文排版，并生成 Markdown 与 HTML 预览。

模型可以选择角色和只读工具，但角色白名单、工具权限、参数模式、调用预算、停止条件和输出校验均由服务端控制。模型、RAG 或工具不可用时，系统保留已经确认的事实，明确标注缺口并转人工处理，不会伪造工具结果、处置完成或验证成功。

## 项目结构

```text
backend/                    FastAPI、智能体、RAG、Wazuh 接入与持久化
frontend/                   React 安全运营工作台与智能助手
scripts/wazuh/              Wazuh Manager 侧只读告警转发适配器
sample_docs/security_vertical/  安全垂直知识库示例
compose.yaml                基础容器部署
compose.server.yaml         服务器持久化目录覆盖配置
compose.local-llm.yaml      双 GPU 本地 Qwen/vLLM 覆盖配置
app.py                      Windows 本地一键启动入口
```

## 本地开发

### 前置条件

- Windows PowerShell 5.1 或 PowerShell 7
- Python `>=3.12,<3.15`
- Node.js LTS 和 npm
- 可选：Docker Desktop 或 Docker Engine

推荐使用现有 Conda 环境：

```powershell
conda activate ShieldChain
python -m pip install -e ".\backend[test]"
npm ci --prefix frontend
Copy-Item .env.example .env
```

`.env` 只用于本机或服务器私有配置，禁止提交 API Key、密码、Webhook Token、真实告警或客户数据。

### 一键启动

```powershell
python app.py
```

默认地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`
- API 文档：`http://127.0.0.1:8000/docs`

## Docker 部署

基础部署：

```bash
docker compose up -d --build
```

服务器持久化部署：

```bash
docker compose -f compose.yaml -f compose.server.yaml up -d --build
```

浏览器访问 `http://127.0.0.1:8080`。SQLite、知识库和助手数据保存在 Docker 命名卷或服务器持久化目录中；执行 `docker compose down` 默认不会删除数据卷。

## 本地 30B-A3B 模型

本地模型覆盖配置使用 vLLM 启动 `Qwen/Qwen3-30B-A3B-Instruct-2507-FP8`，并将 ShieldChain 后端切换到 OpenAI 兼容接口：

```bash
LOCAL_LLM_CACHE_DIR=/home/user/jhk/huggingface \
docker compose -f compose.yaml -f compose.local-llm.yaml up -d
```

默认推理接口绑定到服务器回环地址 `127.0.0.1:8001`，容器内部模型名为 `shieldchain-qwen3-30b`。当前配置面向两张 24 GB GPU，采用两级流水线并行；启动前需要确保模型权重已完整下载且两张 GPU 有足够空闲显存。

## Wazuh 告警接入

Wazuh Manager 侧适配器位于 `scripts/wazuh/custom-shieldchain`。服务端通过 `WAZUH_WEBHOOK_TOKEN` 校验来源，并按最低告警等级、时间窗口和幂等键持久化待复核事件。

详细步骤见 [Wazuh 只读告警接入](docs/operations/wazuh-read-only-ingestion.md)。

## 验证

后端新增安全运营链路测试：

```powershell
conda run -n ShieldChain python -m pytest `
  backend/tests/integration/api/test_operations_report.py `
  backend/tests/integration/api/test_wazuh_ingestion.py `
  backend/tests/unit/operations/test_operations_report_service.py `
  backend/tests/unit/rag/test_local_semantic_chunking.py -q
```

前端测试与类型检查：

```powershell
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
```

Compose 配置检查：

```bash
docker compose -f compose.yaml -f compose.server.yaml config --quiet
docker compose -f compose.yaml -f compose.local-llm.yaml config --quiet
```

## 文档

- [产品需求](docs/requirements/product-requirements.md)
- [系统设计](docs/architecture/system-design.md)
- [开发路线](docs/plans/development-roadmap.md)
- [Windows 本地开发](docs/operations/local-development.md)
- [Wazuh 只读告警接入](docs/operations/wazuh-read-only-ingestion.md)
- [真实模型与 RAG 验收](docs/reports/live-model-rag-acceptance-2026-07-28.md)
- [安全标准](docs/standards/security-standards.md)

## 安全说明

- 不要提交 `.env`、`backend/data/`、模型权重、数据库、API Key、密码或真实客户数据。
- 默认工具为只读查询；任何真实处置动作都必须经过策略、审批、可信工具网关和结果验证。
- 历史报告和知识库可包含敏感安全信息，部署时应限制网络暴露、访问权限和备份范围。
