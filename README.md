# ShieldChain

ShieldChain 是面向安全运营场景的多智能体分析系统。系统接收 Wazuh 等安全平台转发的真实告警，结合本地知识库、历史调查报告和受授权的只读工具，由专业智能体完成检索、研判、协作和安全运营报告生成。

项目默认坚持“分析与处置分离”：模型可以规划、选择工具和生成建议，但不能绕过确定性安全规则、审批、可信工具网关和执行后验证边界。

## 先用 3 分钟看懂项目

如果你第一次接触 ShieldChain，可以先记住下面五点：

1. **数据从哪里来**：目前主要接收 Wazuh 转发的真实安全告警，也可以导入公开或脱敏数据进行测试。
2. **智能体做什么**：智能体负责查询、分析、补充知识、规划建议和生成报告，不直接获得系统管理员权限。
3. **为什么需要 RAG**：大模型本身不知道项目里的历史事件，也不应凭记忆回答法规和安全知识，因此需要检索本地知识库和历史报告。
4. **为什么还有服务端规则**：模型负责判断“下一步查什么”，服务端负责限制“它最多能查什么、参数是否合法、结果能否执行”。
5. **最终谁负责决定**：当前系统输出的是研判依据和建议，真实封禁、隔离、修复仍由人审批。

ShieldChain 可以理解成位于 Wazuh/XDR 与安全运营人员之间的“智能分析层”：

- 它不是杀毒软件，也不是网络探针；
- 它不替代 Wazuh、Zeek、Suricata 或商业 XDR 的数据采集；
- 它把这些系统产生的数据组织起来，让多个专业角色协作研判；
- 它把知识库、历史经验和当前证据汇总成更容易复核的结果。

## 当前完成度与适用边界

当前版本是可运行的比赛/科研原型，不是可以直接替代企业 SOC/XDR 的生产平台。

**已经可以演示和验证：**

- 真实 Wazuh 告警接入、持久化和前端展示；
- 7 个角色的受控 ReAct 多智能体协作；
- 事件、告警、漏洞、弱口令四类只读工具；
- 文档持久化、分块、向量检索、混合检索和重排；
- 历史调查报告自动进入知识库；
- 安全运营报告生成与 HTML 预览；
- 持久化智能助手和独立模型测试页面；
- DeepSeek API 与本地 Qwen/vLLM 两种推理模式。

**仍需生产化完善：**

- 资产台账、身份系统、工单系统和更多真实数据源；
- 跨数据源事件关联、误报治理和攻击链还原；
- 完整 RBAC、租户隔离、密钥托管、监控和高可用；
- 真实处置动作的审批、回滚、幂等和执行后验证；
- 长期真实数据集上的效果评估。

## 主要功能

- **真实告警接入**：接收、持久化并展示 Wazuh 高风险告警，支持人工复核和关联分析。
- **安全多智能体协作**：专业角色通过 ReAct 循环自主观察、选择工具、分析结果和交接任务。
- **安全运营报告智能体**：校验时间参数，自主选择事件、告警、漏洞、弱密码四类只读 MCP 工具，生成结构化建议、Markdown 和 HTML 预览。
- **RAG 知识库**：支持文档持久化、语义分块、混合检索、向量检索、重排、版本管理和分块查看。
- **智能助手**：结合知识库与历史调查报告回答问题，对话和本地记忆持久化保存。
- **本地模型部署**：提供 vLLM OpenAI 兼容服务配置，可使用 `Qwen3-30B-A3B-Instruct-2507-FP8` 替代外部 DeepSeek API。
- **安全边界**：只向前端公开受控轨迹和可验证结论，不公开私有提示词、思维链、原始凭据或敏感工具结果。

## 系统架构

~~~mermaid
flowchart LR
    A["Wazuh / 安全数据源"] --> B["接入、鉴权与规范化"]
    B --> C["SQLite 事件与告警存储"]
    C --> D["安全运营任务"]
    D --> E["ReAct 总控智能体"]

    E --> F["告警分诊"]
    E --> G["威胁研判"]
    E --> H["知识检索"]
    E --> I["响应规划"]
    E --> J["验证"]
    E --> K["报告"]

    F --> T["只读安全工具"]
    G --> T
    I --> T
    J --> T
    K --> T
    H --> R["RAG 知识库"]

    T --> L["公开观察与角色交接"]
    R --> L
    L --> N["运营报告综合生成"]
    N --> O["前端展示与人工复核"]
    O -. "审批后" .-> P["可信工具网关 / 外部处置系统"]
~~~

系统分为四层：

- **数据层**：保存告警、事件、报告、知识库、对话历史和审计信息；
- **工具层**：向智能体暴露经过白名单限制的只读查询能力；
- **智能体层**：由总控和专业角色完成规划、观察、工具调用和交接；
- **展示与控制层**：前端显示结果，由人决定是否进入真实处置。

## 一次安全分析如何完成

以“一段时间内出现多个高风险告警”为例：

1. Wazuh 将达到阈值的告警发送到 ShieldChain；
2. 后端校验 Webhook Token、时间字段、严重等级和幂等键；
3. 告警写入 SQLite，并形成待人工复核事件；
4. 用户在安全运营报告页面选择时间范围并启动任务；
5. 总控智能体查看公开状态，选择下一位专业智能体；
6. 专业智能体根据职责和工具说明决定是否调用工具；
7. 角色只公开摘要、观察和交接理由，不公开私有思维链；
8. 报告综合环节区分已确认事实、工具线索、知识依据和未知项；
9. 系统生成中文报告、Markdown 和 HTML 预览；
10. 安全人员复核后，再决定是否封禁、隔离、修复或继续取证。

### ReAct 在本项目中的含义

每个专业角色在有限轮次内执行“观察—行动—再观察”：

1. 阅读职责、前序交接和当前观察；
2. 阅读获授权工具的用途、适用场景、禁用场景和证据限制；
3. 调用一个工具，或者在证据已经足够时结束；
4. 获取服务端返回的受控观察；
5. 再判断是否需要其他工具；
6. 输出不含私有推理的公开中文摘要。

模型不能无限循环，也不能选择角色白名单之外的工具。同一工具在一次角色运行中只执行一次，后续读取缓存结果。

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

## 前端页面怎么用

| 页面 | 作用 |
| --- | --- |
| **主页/运营总览** | 查看系统入口、运行状态和主要能力。 |
| **告警中心** | 查看接入的 Wazuh 告警、规则与风险等级。 |
| **安全运营报告** | 选择时间范围，启动多智能体分析并预览报告。 |
| **历史报告** | 查看已保存的调查报告、详情、审计记录和操作入口。 |
| **智能体工作区** | 查看公开协作轨迹和受控 ReAct 轨迹，不展示私有思维链。 |
| **知识库** | 管理文档、版本、分块、索引和混合检索。 |
| **智能助手** | 基于知识库和历史报告进行持久化安全问答。 |
| **模型测试** | 直接测试 Qwen 或当前兼容模型，不经过 RAG 主链路。 |
| **处置/工具页面** | 查看受控操作入口，真实动作仍需要策略和人工审批。 |
| **状态与帮助** | 查看组件状态、版本和使用说明。 |

### 智能助手和模型测试的区别

- **智能助手**会检索知识库和历史调查报告，保存对话，并遵守证据约束；
- **模型测试**直接体验基础模型，用来确认 Qwen/vLLM 是否正常；
- 模型测试能够回答，不表示 RAG 链路正常；
- 智能助手检索不到安全依据时会明确说明，但“你好”“你是谁”等寒暄会由模型自然回复。

### 智能体工具说明

模型收到的不只是工具名称，还会看到 description、use_when、do_not_use_when、parameters、returns 和 limitations。

| 工具 | 用途 | 证据限制 |
| --- | --- | --- |
| security.events.list | 查询由告警归并形成的待复核事件。 | 不代表威胁已经确认。 |
| security.alerts.list | 查询 Wazuh 规则、等级和告警标题。 | 可能误报、重复或缺少上下文。 |
| security.vulnerabilities.list | 从告警中提取 CVE 和关联线索。 | 出现 CVE 不等于资产确定受影响。 |
| security.weak_passwords.list | 筛选密码喷洒、暴力破解等认证风险。 | 不读取密码，也不能直接确认弱口令。 |
| knowledge.rag.retrieve | 检索知识库和历史调查报告。 | 知识不能证明当前事件事实。 |

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

## 选择哪种启动方式

| 场景 | 推荐方式 | 模型来源 |
| --- | --- | --- |
| Windows 开发和调试 | python app.py | .env 中的 DeepSeek 或兼容接口 |
| 快速容器演示 | compose.yaml | .env 中的模型配置 |
| 服务器持久化 | compose.yaml + compose.server.yaml | .env 中的模型配置 |
| 双 4090 本地模型 | 再叠加 compose.local-llm.yaml | Qwen3-30B-A3B + vLLM |

第一次启动前建议先运行：

~~~powershell
python app.py --check
~~~

app.py 常用选项：

~~~text
--check            只检查依赖和配置
--no-browser       启动后不自动打开浏览器
--skip-migrations  跳过 Alembic 数据库迁移
~~~

### DeepSeek 和本地 Qwen 为什么使用同一组变量

项目使用统一的 OpenAI 兼容客户端。DEEPSEEK_BASE_URL、DEEPSEEK_MODEL 和 DEEPSEEK_API_KEY 是早期沿用的变量名，既可以连接 DeepSeek，也可以连接本地 vLLM/Qwen。

本地 Qwen 覆盖配置会自动使用：

~~~dotenv
DEEPSEEK_BASE_URL=http://local-llm:8000/v1
DEEPSEEK_MODEL=shieldchain-qwen3-30b
DEEPSEEK_API_KEY=local-vllm
~~~

其中 local-vllm 是本地兼容接口的占位鉴权值，不是 DeepSeek 密钥。

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

## 常见问题

### 不调用 LLM 还算智能体吗？

如果只有固定状态机和规则判断，更接近自动化工作流。ShieldChain 的 ReAct 角色会调用模型观察上下文并自主选择获授权工具，服务端规则负责权限和安全边界。

### 为什么显示“保守降级”？

表示模型、RAG 或工具不可用，系统只保留已确认事实并转人工。降级不代表 LLM 调用成功，也不代表处置完成。

### 为什么智能助手有时不直接回答？

安全知识问题需要知识库或历史报告依据。检索不到时助手会说明资料不足，避免编造。普通寒暄不需要 RAG，会由模型自然回复。

### 为什么模型测试能回答，智能助手却说资料不足？

模型测试直接体验基础模型；智能助手必须遵守知识依据约束。模型“知道一些东西”不等于项目知识库已经提供了可追溯证据。

### 知识库关机后还在吗？

只要使用相同持久化目录或 Docker 数据卷，并且没有执行 down -v 或主动删除，知识库、报告和助手对话都会保留。

### 可以直接用于生产封禁吗？

不建议。当前重点是分析、检索、报告和人工复核。生产处置还需要企业审批、IAM、工单、回滚和审计。

### 服务器没有桌面环境，怎么打开前端？

通过 SSH 端口转发把服务器的 127.0.0.1:8080 映射到本机，再用本机浏览器访问。

### 没有交换机镜像流量还能演示吗？

可以使用 Wazuh 终端告警、公开/脱敏数据集和受控测试数据。没有 SPAN/TAP 时不能声称已经采集整个网络的真实镜像流量。

## 推荐阅读顺序

1. 本 README 的“先用 3 分钟看懂项目”和“系统架构”；
2. docs/architecture/system-design.md；
3. docs/architecture/multi-agent-design.md；
4. docs/architecture/rag-design.md；
5. 启动后依次体验告警中心、安全运营报告、知识库、智能助手和模型测试。

遇到异常时，请记录启动方式、当前分支、浏览器报错、后端日志和复现步骤。这样其他同学才能判断问题来自前端、后端、模型、RAG、数据库还是网络。

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
