# ShieldChain MCP、响应规划、智能体工具与安全闭环统一实施方案

> 文档状态：实施中（2026-08-22）。Task 0～1 已完成，Task 2～14 尚待实施。本文是后续开发、评审、测试、迁移和 Git 提交的执行基线。实施过程中如果改变协议版本、安全边界、数据模型或任务顺序，必须先更新本文并在当日开发日志中记录原因、替代方案和迁移影响。

## 1. 文档目的

本文补齐当前仓库缺少的统一实现说明，并把以下四条原本分散的链路收敛为一套可验证设计：

1. 使用标准 Model Context Protocol（MCP，模型上下文协议）向外发布 ShieldChain 的只读安全工具；
2. 通过受控 MCP Client 接入经过管理员配置的外部只读安全工具；
3. 让响应规划智能体输出严格、可验证、只代表候选建议的结构化响应计划；
4. 把候选计划、可信工具网关、执行回执、新遥测、执行后验证、重新规划和人工接管连接成安全闭环。

本文只定义执行方案，不把尚未实现的能力描述为已经完成。所有功能状态仍以当前代码、`docs/README.md` 和根目录 `README.md` 为准。

## 2. 当前事实与主要缺口

### 2.1 可复用实现

| 当前模块 | 已有能力 | 后续处理 |
| --- | --- | --- |
| `operations/mcp_tools.py` | 事件、告警、漏洞线索、弱口令线索四类租户化只读查询 | 提取为协议无关的内置 Agent Tool Provider；保留兼容适配直至调用方迁移完成 |
| `operations/react_collaboration.py` | 模型选择角色和只读工具、单角色最多四轮、结果缓存、安全降级 | 改为使用统一工具目录和调用审计；响应规划角色改为严格 Schema 输出 |
| `agents/` | 角色、上下文、交接、预算、结构化领域合同 | 保留并接入通用运行模型；不恢复已经退役的旧调查页面 |
| `tools/` | 工具注册、策略、审批、幂等、租约、执行、验证、恢复和控制 | 继续作为唯一可信变更执行边界；外部 MCP 不能绕过它 |
| `react/` | 失败分类、预算、循环检测、确定性重新规划、轨迹和人工控制 | 接入当前运营链路的通用运行 ID、响应计划和真实工具回执 |
| `/api/v1/tools/*`、`/api/v1/react/*` | 可信工具与 ReAct 公开轨迹、审批和人工控制 | 保持兼容，在新运行模型上扩展，不把 MCP 传输端点放入 REST 路由 |
| `/operations-report`、`/agents`、`/response` | 运营报告、公开 ReAct 轨迹和处置中心页面 | 增加统一运行、响应计划、MCP 调用来源和闭环状态展示 |

### 2.2 必须补齐的缺口

- 当前所谓 MCP 是进程内 Python façade，没有标准 MCP Server、MCP Client、协议协商、标准传输或兼容性测试；
- 当前运营报告以本地 JSON 文件保存，没有通用 `run_id`，无法稳定关联工具调用、响应计划、审批、执行、验证和重新规划；
- 当前响应规划主要是自然语言摘要或 `proposed:` 字符串，缺少现行的严格输出 Schema、计划编译器、证据重绑定和版本化持久化；
- 当前 `operations` 工具目录、角色白名单和执行器写在同一个模块中，不能同时安全服务内部调用、MCP 发布和外部 MCP 导入；
- 当前阶段 4～6 数据模型依赖早期 `investigation_runs`，而该表又依赖已退役的仿真事件，不能直接代表当前安全运营报告运行；
- 尚未形成“动作回执 → 新遥测 → 验证 → 重新规划/人工接管”的生产闭环；
- 尚无 MCP 鉴权、Origin 校验、SSRF 防护、远端 Schema 固定、结果大小限制、速率限制、熔断、Token 隔离和协议级审计；
- 尚无 MCP 官方一致性测试和外部平台兼容性验收证据。

## 3. 完成定义

只有同时满足以下条件，项目才可以把本阶段标记为完成：

1. `/mcp` 是可由官方 MCP Client 发现和调用的标准 Streamable HTTP 端点；
2. 四类内置只读工具既可由内部智能体调用，也可通过 MCP 发布，但两条路径复用同一领域服务和授权规则；
3. 至少一个测试用外部 MCP Server 可通过受控 Client 完成发现、Schema 固定、调用、结果裁剪和审计；
4. 响应规划产生版本化、带证据引用的严格计划，模型不能指定最终风险、权限、审批结果、租户、主体或幂等键；
5. 变更动作只能由现有 `tools/` 可信网关执行，并且只有执行后验证成功才能报告成功；
6. 失败、超时、结果未知、验证失败、预算耗尽和循环重复均有确定性分支，不会被解释为安全或成功；
7. 当前运营报告拥有通用运行 ID，可关联智能体轨迹、Agent Tool 调用、响应计划、可信工具、ReAct 决策和最终报告；
8. 生产环境未配置真实认证、授权和 TLS 边界时，MCP 网络入口必须启动失败或保持关闭；
9. 后端、前端、迁移往返、Compose、MCP 一致性、安全回归和端到端 smoke 全部通过；
10. 文档、配置示例、部署步骤、回滚步骤和实际验收记录与代码一致。

## 4. 协议与依赖基线

### 4.1 协议版本决策

实现以 MCP `2026-07-28` 为主协议版本。该版本使用无协议会话的请求模型，每个请求在 `_meta` 中携带协议版本、客户端信息和能力；Streamable HTTP 的每个 JSON-RPC 消息使用独立 POST，并通过标准请求头提供协议版本、方法和工具名称。

兼容策略如下：

| 项目 | 决策 |
| --- | --- |
| 主协议版本 | `2026-07-28` |
| 兼容版本 | 通过官方 Python SDK v2 自动兼容 `2025-11-25` 客户端；不自行维护第二套 JSON-RPC 编解码器 |
| 服务端传输 | Streamable HTTP，挂载在 `/mcp` |
| 外部客户端传输 | 第一版只允许 Streamable HTTP |
| stdio | 服务端部署禁止；不允许通过配置启动任意本地子进程 |
| HTTP+SSE | 不新增；该旧传输已经被 Streamable HTTP 取代并进入弃用路径 |
| MCP 能力 | 第一版仅 `tools`；不发布 Resources、Prompts、Roots、Sampling 或协议 Logging |
| Python SDK | 官方 `mcp` 2.x，依赖范围写为 `mcp>=2,<3`，实际构建解析版本进入交付清单 |
| JSON Schema | 采用 JSON Schema 2020-12；业务层仍施加更严格的字段、长度、枚举和范围限制 |

不得根据客户端自报的 `clientInfo`、工具 annotation 或工具描述做授权决策。它们只用于兼容性、展示和审计摘要。

### 4.2 官方基线

实施和评审必须以以下官方材料为准：

- [MCP 2026-07-28 发布说明](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/blog/content/posts/2026-07-28-spec-ga/index.md)
- [MCP 2026-07-28 Streamable HTTP 规范](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx)
- [MCP 2026-07-28 Tools 规范](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx)
- [MCP 2026-07-28 Authorization 规范](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/index.mdx)
- [MCP Authorization 安全要求](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx)
- [官方 MCP Python SDK v2 文档](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/index.md)
- [官方 Python SDK 协议版本说明](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/protocol-versions.md)

每次升级 MCP SDK 前必须重新核对规范版本、SDK 支持矩阵、安全公告和一致性测试结果，不能只修改依赖版本。

## 5. 范围与非目标

### 5.1 第一版必须实现

- 标准 MCP Server 和 `/mcp` Streamable HTTP 路径；
- 四类内置只读工具的标准 `tools/list` 与 `tools/call`；
- 统一 Agent Tool 领域合同、目录、策略、Broker、结果包络和审计；
- 受控外部 MCP Client、固定配置、工具快照和只读调用；
- 通用智能体运行表和当前运营报告运行接线；
- 结构化响应计划、计划编译、版本化持久化和公开投影；
- 响应计划到可信工具调用的显式映射；
- 工具结果、新遥测、验证、失败分类、重规划和人工接管接线；
- MCP 状态、工具目录、调用轨迹、响应计划和闭环状态的只读界面；
- MCP 协议、授权、安全、限额、故障和迁移测试；
- 本地、容器和服务器部署及回滚文档。

### 5.2 第一版明确不实现

- 不允许模型、Skill、RAG 文档或普通 HTTP 用户动态添加 MCP Server；
- 不执行外部 MCP Server 提供的任意脚本、Shell、PowerShell、Node.js 或二进制程序；
- 不支持生产 stdio MCP Server，不拉起第三方子进程；
- 不把外部 MCP 工具的 `readOnlyHint`、名称或描述直接当作安全分类；
- 不把外部状态变更 MCP 工具直接加入智能体工具目录；
- 不通过 MCP 暴露封禁、隔离、停用账号等真实变更动作；
- 不自行实现 OAuth Authorization Server；生产环境接入现有身份提供方；
- 不支持 MCP Resources、Prompts、Roots、Sampling、协议 Logging、MCP Apps 或 Tasks 扩展；
- 不保存或展示模型隐藏思维链、私有提示、原始 MCP 载荷、访问令牌或设备凭据；
- 不在没有获授权测试环境时连接真实防火墙、EDR、账号系统或深信服生产数据；
- 不为了比赛展示绕过人工审批、租户边界、执行后验证或紧急停止。

## 6. 名词与权限边界

| 概念 | 含义 | 能否授予权限 | 能否改变外部状态 |
| --- | --- | --- | --- |
| Knowledge | 通过 RAG 提供事实、规范和历史材料 | 否 | 否 |
| Skill | 给智能体提供过程步骤、检查点和输出要求 | 否，只能收窄有效工具集合 | 否 |
| Agent Tool | 智能体可请求的协议无关能力，第一版仅只读查询和受控检索 | 不能自行授予，必须由服务端目录和策略授权 | 第一版否 |
| MCP Adapter | 把 Agent Tool 发布为 MCP，或把外部 MCP Tool 包装成 Agent Tool | 否，只做协议转换 | 不决定 |
| Trusted Tool | 由服务端注册、可能改变状态的可信工具 | 由服务端策略决定 | 可以，但必须审批和验证 |
| Response Plan | 响应规划智能体提出的候选动作和验证条件 | 否 | 否 |
| Tool Approval | 绑定调用摘要、策略版本和审批主体的授权记录 | 是，但只对一个固定请求生效 | 本身不执行 |
| ReAct Loop | 对受信观察进行分类并决定查询、重试、重规划或转人工 | 否 | 不直接执行 |

有效工具集合必须始终是交集：

```text
effective_agent_tools =
    role_allowed_tools
    ∩ tenant_enabled_tools
    ∩ server_policy_allowed_tools
    ∩ run_catalog_snapshot
    ∩ skill_requested_tools（若 Skill 有声明）
```

任何输入都不能通过声明工具名、MCP annotation、`allowed-tools`、风险等级或角色名称扩大这个集合。

## 7. 核心安全不变量

以下不变量必须由领域模型、服务层和测试共同强制，不能只依靠 Prompt：

1. tenant、principal、role、run、case、权限、风险和预算来自服务端可信上下文；
2. 内部智能体调用本地工具时不经过 `/mcp` 回环请求；MCP 只是边界适配器，不是授权机制；
3. 所有工具参数在执行前按服务器拥有的 Schema 再校验；
4. 模型产生的目标字符串必须重新解析为同租户、同案件的已确认实体或证据引用；
5. 外部 MCP 工具和结果默认不可信，必须经过管理员映射、目录固定和结果裁剪；
6. MCP 访问令牌不能透传给下游服务；每个远端使用独立受众和凭据；
7. 工具列表在一次运行开始时固定摘要，运行中远端目录变化只影响新运行；
8. 只读调用失败、超时或空结果分别保存，失败不能降格为空结果；
9. 响应计划只是候选，不能直接变成执行请求；
10. 审批绑定规范化请求摘要，参数、工具版本、目标或证据变化后旧审批失效；
11. 变更动作超时只代表结果未知，禁止盲目重放；
12. 成功必须由执行后验证和新的可信观察证明，适配器返回成功不等于业务成功；
13. 预算、循环检测、全局自动化开关和紧急停止在发放新工具租约前检查；
14. 所有公开结果只包含 allowlist 字段，不包含原始工具载荷、凭据、私有异常或思维链；
15. 同一运行的计划、调用、验证、观察和决策必须绑定相同 tenant、case、run 和 revision 边界。

## 8. 目标架构

```text
外部 MCP Client
       │  OAuth/TLS + Streamable HTTP
       ▼
   /mcp Protocol Adapter ───────────────┐
                                        │
当前运营报告 / 多智能体 ────────────────┼──► AgentToolBroker
                                        │        │
受控外部 MCP Client ─► Remote Adapter ──┘        ├──► 内置只读 Provider
                                                 ├──► RAG Provider
                                                 └──► 获批准的外部只读 MCP Provider
                                                          │
                                                          ▼
                                               裁剪结果 + 调用审计

公开观察 + 证据引用
       ▼
响应规划智能体 ─► ResponsePlanCandidate
       ▼
计划编译器：工具解析、目标重绑定、Schema 校验、证据校验、计划版本化
       ▼
ResponsePlan（仍未授权）
       ▼
可信工具网关：策略 ─► 审批 ─► 幂等/租约 ─► Adapter ─► 执行记录
       ▼
只读验证器 / 新遥测
       ▼
结构化观察 ─► 失败分类 ─► 完成 | 查询状态 | 只读重试 | 重规划 | 人工接管
```

### 8.1 内部调用与 MCP 发布复用方式

四类内置工具的 SQL 查询和结果裁剪只实现一次：

- 内部智能体通过 `AgentToolBroker` 直接调用 Provider；
- `/mcp` 通过 MCP Server Adapter 调用同一个 Broker；
- 两条路径使用相同的租户、主体、参数、大小、字段和审计规则；
- MCP Adapter 不直接 import SQLAlchemy Row，也不自行拼装结果；
- 不允许内部智能体调用 `http://127.0.0.1/.../mcp`，避免额外网络故障和身份混淆。

### 8.2 目标文件组织

Agent Tool 继续复用现有 `operations` 模块，不为协议去耦单独建立领域包。只有标准 MCP 网络边界开始实现时才新增最小 `mcp/` 模块；响应计划拥有独立状态和持久化需求时再新增 `response_planning/`。

```text
backend/src/shieldchain/
  operations/
    mcp_tools.py           # 现有四类只读 Provider；保留旧 façade 兼容名
    react_collaboration.py # 现有目录、角色白名单和 AgentToolBroker
    service.py             # 当前运营报告入口
  mcp/
    server.py              # 第一阶段 MCPServer 构建、工具注册和 ASGI 挂载
    authority.py           # 网络启用时增加的可信身份映射
    client.py              # 外部 MCP 确认需要时增加的受控 Client
  response_planning/
    __init__.py
    domain.py              # 计划、修订、动作、验证和状态合同
    candidate_schema.py    # 模型输出严格 Schema
    compiler.py            # 服务端重绑定与规范化
    service.py
    persistence.py
    repositories.py
    schemas.py             # 公开 API 投影
    api_service.py
```

现有 `tools/` 目录继续专门表示可信变更工具，不改名。`operations` 中的只读 Agent Tool 与 `tools/` 中的可信变更工具必须在命名、文档和代码评审中保持明确。

## 9. 统一 Agent Tool 领域合同

### 9.1 `AgentToolDefinition`

每个工具定义必须包含：

- `identity`：服务端内部不可变 UUID；
- `alias`：提供给模型的稳定名称，例如 `security.alerts.list`；
- `provider_kind`：`builtin`、`rag` 或 `remote_mcp`；
- `provider_id`：内置 Provider ID 或固定远端 ID；
- `remote_name`：仅外部 MCP 使用，不能代替内部 alias；
- `version`：本地策略版本，不盲信远端版本字符串；
- `title`、`description`、`use_when`、`do_not_use_when`、`limitations`；
- `input_schema`、`output_schema` 和服务端维护的 `schema_revision`；
- `classification`：第一版只允许 `read_only`；
- `allowed_roles`；
- `timeout_seconds`、`max_result_bytes`、`max_items`；
- `cache_policy`：是否允许单运行缓存以及 TTL；
- `enabled` 和单调递增的 `catalog_revision`。

工具描述用于模型选择，但授权只依据服务器保存的 identity、classification、allowed roles 和策略版本。

### 9.2 `AgentToolInvocation`

调用对象由服务端构造，至少包含：

- `call_id`、`request_id`、`tenant_id`、`principal_id`；
- `run_id`、`case_id` 和 `role`；外部直接 MCP 查询可以没有 run/case，但仍必须有认证主体；
- 固定的 `tool_identity`、`alias`、`catalog_revision` 和 `schema_revision`；
- 已校验的规范化参数和参数摘要；
- 调用预算快照、创建时间和绝对 deadline。

HTTP/MCP 请求不能提供或覆盖 tenant、principal、role、classification、目录/Schema revision、预算或审计主体。

### 9.3 `AgentToolResult`

结果状态使用固定枚举：

- `succeeded`：查询成功且返回一个或多个受控结果；
- `empty`：查询成功且结果确实为空；
- `failed`：依赖明确失败；
- `timed_out`：达到 deadline，结果未取得；
- `cancelled`：调用方取消或连接断开；
- `rejected`：授权、Schema、目录固定或安全策略拒绝。

结果包含 `structured_content`、公开 `summary`、可信引用、结果数量、原因码、耗时和截断标记。原始 SQL Row、HTTP body、远端 MCP content、堆栈和凭据不进入领域结果。

### 9.4 四类内置工具的标准 Schema

四类工具使用同一输入形状：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "start_at": {"type": "string", "format": "date-time"},
    "end_at": {"type": "string", "format": "date-time"},
    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 50}
  },
  "required": ["start_at", "end_at"]
}
```

额外业务约束：

- 时间必须带时区并规范化到 UTC；
- `start_at <= end_at`；
- 单次范围不超过 31 天；
- 只查询认证主体所属 tenant；
- 排序稳定并带唯一稳定标识；
- items 最多 50 条，单条公开摘要最多 512 字符；
- CVE 和弱口令结果必须保留“仅为线索”的限制说明。

统一输出 Schema：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "status": {"enum": ["succeeded", "empty"]},
    "result_count": {"type": "integer", "minimum": 0, "maximum": 50},
    "summary": {"type": "string", "maxLength": 1000},
    "items": {
      "type": "array",
      "maxItems": 50,
      "items": {"type": "object"}
    },
    "limitations": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 512}},
    "truncated": {"type": "boolean"}
  },
  "required": ["status", "result_count", "summary", "items", "limitations", "truncated"]
}
```

上面是公共结果包络；每类工具的最终 output Schema 必须把 `items.items` 替换为带 `properties`、`required` 和 `additionalProperties=false` 的具体 allowlist 对象，不能用公共示例中的自由对象直接进入实现。

## 10. MCP Server 实现

### 10.1 路由和生命周期

- MCP ASGI App 挂载到现有 FastAPI 应用的 `/mcp`；
- REST API 继续使用 `/api/v1`，两者不能共用请求/响应 Schema；
- MCP Server 与 FastAPI 共享数据库连接工厂、Agent Tool Catalog 和应用生命周期；
- 启动时先构建并验证工具目录，重复名称、Schema 错误或安全分类缺失必须导致 MCP 子系统拒绝启动；
- `MCP_SERVER_ENABLED=false` 时不挂载 `/mcp`，返回普通 404；
- 应用关闭时停止接受新请求，等待有上界的只读调用结束并关闭 SDK 资源。

### 10.2 2026-07-28 请求要求

主版本请求必须满足：

- 每个请求为独立 HTTP POST；
- `Content-Type: application/json`；
- `Accept` 同时允许 `application/json` 和 `text/event-stream`；
- `MCP-Protocol-Version: 2026-07-28`；
- `Mcp-Method` 与 JSON-RPC method 一致；
- `tools/call` 的 `Mcp-Name` 与 `params.name` 一致；
- `_meta.io.modelcontextprotocol/protocolVersion` 与请求头一致；
- 缺失、冲突或不受支持的版本返回明确协议错误，不能降级成业务空结果；
- 不依赖 `Mcp-Session-Id`；跨调用业务状态使用服务端生成、绑定主体且有过期时间的显式 handle。

上述线级行为优先由官方 SDK 完成，ShieldChain 只增加业务授权、Origin、大小、限额和审计中间层，不复制 SDK 的 JSON-RPC 实现。

### 10.3 `tools/list`

- 只返回调用主体在当前 tenant 可见的工具；
- 第一版对外只发布四类内置只读工具；
- 工具顺序按 alias 字节序稳定排序；
- Schema 使用 JSON Schema 2020-12；
- 每项包含 title、description、inputSchema、outputSchema 和只读提示；
- annotations 只是客户端提示，服务端授权仍以内部目录为准；
- list 结果携带官方支持的缓存提示；目录 revision 改变后缓存失效；鉴权相关响应必须使用私有缓存并按可信授权上下文隔离，禁止跨 tenant/principal 共享；
- 不向外发布 RAG、可信变更工具、远端转发工具或内部调试工具。

### 10.4 `tools/call`

调用流程固定为：

1. 验证协议、HTTP 方法、Content-Type、Accept、Origin 和请求体大小；
2. 验证 OAuth Access Token，得到 tenant、principal 和 scopes；
3. 将 scope 映射到本地 Agent Tool 权限；
4. 解析 alias，并从服务器目录获取不可变定义；
5. 校验 JSON Schema、时间范围、字段长度和业务边界；
6. 构造 `AgentToolInvocation`；
7. 通过 Broker 执行 Provider；
8. 裁剪输出，保存调用审计；
9. 返回 MCP `structuredContent` 和简短 TextContent；
10. 在任何异常情况下使用稳定错误类别，不返回堆栈、SQL、内部路径或原始依赖载荷。

业务参数错误应作为 Tool Execution Error 返回，使客户端或模型可以修正；只有 JSON-RPC 包络、方法和协议错误使用 Protocol Error。

### 10.5 Origin、Host 和反向代理

- 所有带 Origin 的 MCP 请求必须与 `MCP_ALLOWED_ORIGINS` 精确匹配，否则返回 403；
- 本地开发只绑定回环地址；生产由现有反向代理提供 TLS；
- Nginx 增加独立 `location /mcp`，关闭代理缓冲和缓存，允许请求范围内 SSE，保留 `Authorization`、`MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 和 `X-Request-ID`；
- Nginx 和后端都施加请求体、响应体、连接、发送和读取超时；
- 不信任客户端传入的 `X-Forwarded-*`，可信代理拓扑在部署层显式配置；
- CORS 配置不能代替 MCP Origin 检查或 OAuth。

### 10.6 鉴权

生产 MCP Server 作为 OAuth 2.1 Resource Server：

- 使用现有或单独部署的 Authorization Server，不在 ShieldChain 内签发用户令牌；
- 验证签名、issuer、audience/resource、有效期、not-before、scope 和撤销/轮换状态；
- 支持 OAuth Protected Resource Metadata；
- scopes 最小化，例如 `shieldchain:events:read`、`shieldchain:alerts:read`、`shieldchain:vulnerabilities:read`、`shieldchain:auth-risk:read`；
- tenant 和 principal 从已验证 claims 经过服务端映射得到，不能直接相信任意同名 claim；
- token 只在内存中参与验证，不写日志、数据库或报告；
- `MCP_AUTH_MODE=disabled` 只允许 `testing`，开发环境若需真实 HTTP 必须使用测试身份提供方或短期测试令牌；
- `production + MCP_SERVER_ENABLED=true + 非 oauth` 必须在 Settings 校验阶段启动失败。

## 11. 受控外部 MCP Client

### 11.1 配置来源

外部 MCP Server 只能由服务器管理员通过固定配置文件声明。仓库提交 `config/mcp/servers.example.yaml`，实际文件由 `MCP_REMOTE_CONFIG_PATH` 指定且不提交 Git。

配置只保存公共元数据和 Secret 引用，不保存明文凭据：

```yaml
version: 1
servers:
  - id: approved-security-platform
    enabled: false
    transport: streamable_http
    endpoint: https://security-platform.example.invalid/mcp
    auth:
      mode: bearer_env
      token_env: APPROVED_SECURITY_PLATFORM_MCP_TOKEN
    network_policy: public_https
    allowed_tools:
      - remote_name: alerts_list
        alias: external.approved_security_platform.alerts.list
        classification: read_only
        allowed_roles: [alert_triage, threat_investigation]
```

示例必须保持 `enabled: false` 和 `.invalid` 域名，防止误连。实际 endpoint、远端工具名、scope 和凭据由部署环境提供。

### 11.2 发现和目录固定

1. 启动时严格解析配置，拒绝额外字段、重复 ID、任意 transport 和未知 auth 模式；
2. 解析 endpoint，执行协议、主机、端口、DNS、地址范围和 TLS 策略；
3. 使用官方 Client `auto` 模式探测 2026-07-28，并在允许时兼容 2025-11-25；
4. 调用 `tools/list`，限制页数、工具总数、名称长度、描述长度和 Schema 大小；
5. 只接受配置 `allowed_tools` 中逐项映射的 remote name；
6. 校验并保存 input/output Schema、远端名称、发现时间、协议版本和服务端 Schema revision；
7. 管理员配置的 classification 和 role allowlist 是本地权威，远端 annotation 只作审计对照；
8. 一次智能体运行保存 catalog revision，运行期间远端变化不替换该快照；
9. 远端 Schema 与已批准结构不一致时停止该工具新调用并产生 `mcp_schema_changed`，由管理员更新配置或批准新 revision，不计算额外哈希；
10. 刷新失败保留最近已知目录只用于展示，不能在过期后继续新调用。

### 11.3 SSRF 和网络策略

- 默认只允许 HTTPS 和端口 443；
- 禁止 URL 用户信息、fragment、非空不受控 query 和动态路径拼接；
- 默认拒绝 loopback、link-local、multicast、unspecified、云元数据地址和私网地址；
- 校内/内网 MCP 必须使用显式 `internal_https` policy 和固定 CIDR allowlist；
- DNS 解析结果必须全部满足网络策略，请求建立后校验实际连接目标，防止 DNS rebinding；
- 默认禁止重定向；确需重定向时只允许同 scheme、同 host、同 port；
- TLS 证书验证不能关闭；私有 CA 通过只读 CA bundle 注入；
- 代理设置由服务端管理员固定，不能从模型参数或 MCP 结果读取；
- 每个 peer 使用独立连接池、并发上限、速率限制和熔断状态。

### 11.4 凭据隔离

- 不把 ShieldChain 入站用户 Token 直接发送给远端；
- 每个远端使用独立的 OAuth client 或独立 bearer secret；
- token 的 audience/resource 必须绑定目标 MCP Server；
- `bearer_env` 支持用于获授权的现有平台，但必须记录轮换责任和过期告警；
- 支持 OAuth Client Credentials 时必须使用目标平台正式支持的授权扩展和独立 scope；
- Access Token 只在内存缓存到期时间内存在；刷新失败立即停止调用；
- 日志只记录 peer ID、认证模式和稳定错误码，不记录 header 或 token 摘要。

### 11.5 外部调用限制

| 限制 | 第一版默认值 |
| --- | --- |
| 单 peer 工具数 | 100 |
| `tools/list` 总 Schema 大小 | 1 MiB |
| 单工具 input/output Schema | 各 64 KiB |
| 单次请求体 | 256 KiB |
| 单次原始响应读取上限 | 2 MiB，超限立即中止且不持久化原文 |
| 单次公开结构化结果 | 64 KiB |
| 连接超时 | 5 秒 |
| 总调用 deadline | 30 秒 |
| 单运行外部 MCP 调用数 | 10，且受全局 ReAct 工具预算更小值约束 |
| 单 peer 并发 | 4 |
| 连续失败熔断 | 5 次失败后打开 60 秒 |

这些默认值进入 Settings 且有硬上界。调用方不能通过参数扩大。

### 11.6 外部状态变更工具

第一版统一拒绝。未来如需接入外部防火墙或 EDR MCP Tool，必须把它包装为本地 `TrustedToolDefinition` 和 Adapter，并明确：

- 固定版本和参数类型；
- 目标从同租户证据解析；
- 风险和审批策略；
- 幂等语义；
- 超时和结果未知语义；
- 配对只读状态查询；
- 执行后验证器；
- 回滚策略和人工恢复步骤。

满足上述条件后，模型看到的仍是响应计划中的本地可信动作名，不直接看到或调用远端变更 MCP Tool。

## 12. 响应规划详细设计

### 12.1 输入边界

响应规划智能体只接收：

- 服务端生成的任务目标和当前 run/case 摘要；
- 已确认事实、待验证假设和风险的公开投影；
- 同案件证据引用和必要的知识引用；
- 当前固定 Agent Tool 目录中允许该角色使用的只读工具说明；
- 可提议的 `TrustedToolDefinition` 公共能力摘要，不含凭据、审批规则细节或 Adapter；
- 当前计划 revision、剩余预算和必须遵守的输出 Schema；
- 上游结构化交接的公开字段。

工具原始结果、私有 Prompt、其他角色私有上下文、设备凭据、审批主体、内部策略条件和数据库连接不得进入模型上下文。

### 12.2 模型候选 Schema

模型必须只输出一个 JSON 对象；Markdown 代码块标记、前后解释文字或第二个对象都视为无效，也不从自由文本抽取可执行命令：

```json
{
  "action": "propose_response_plan",
  "public_summary": "建议先确认防火墙当前状态，再由人工审批是否封禁已确认恶意源地址。",
  "assumptions": [
    {
      "statement": "目标地址已经由同案件证据确认",
      "evidence_ids": ["00000000-0000-4000-8000-000000000000"]
    }
  ],
  "actions": [
    {
      "client_action_id": "step-1",
      "tool": "query_firewall_state",
      "target_reference_id": "00000000-0000-4000-8000-000000000000",
      "arguments": {},
      "expected_state": {"state_observed": true},
      "depends_on": [],
      "public_reason": "先获取可信当前状态，避免对未知结果重复变更。",
      "verification": {
        "tool": "query_firewall_state",
        "expected_state": {"state_observed": true}
      },
      "rollback_note": "只读动作无需回滚。"
    }
  ],
  "stop_conditions": ["证据冲突", "目标无法从证据解析", "预算不足"],
  "operator_notes": ["任何变更动作必须单独审批"]
}
```

Schema 强制：

- `additionalProperties=false`；
- 一份计划最多 8 个动作；
- 字符串逐字段设置上限；
- `client_action_id` 只用于本次解析内依赖，不能作为数据库 ID；
- tool 必须来自服务端提供的可提议动作集合；
- target 只能使用引用 ID，不能直接提供任意 IP、主机名或账号；
- arguments 只允许工具公共候选字段，服务端仍会重新绑定；
- 模型不能输出 tenant、principal、role、risk、approval、policy、idempotency key、timeout、credential、URL、Shell 或代码；
- 模型不能声称已经批准、执行、验证、回滚或完成。

### 12.3 服务端计划编译器

`ResponsePlanCompiler` 按固定顺序处理候选：

1. 验证顶层和动作 Schema；
2. 使用服务端 run/case/tenant/principal/role 覆盖上下文；
3. 重新读取每个 evidence ID，并验证同租户、同案件、完整性、时效和确认状态；
4. 从本地可信工具注册表解析名称和版本；
5. 从证据实体解析真实目标，忽略模型直接构造的目标值；
6. 使用工具参数类型重新构造规范化参数；
7. 检查依赖图无环、引用存在、只向前依赖；
8. 校验 expected state 与工具验证器兼容；
9. 由服务端评估风险、审批要求、回滚能力和预算；
10. 为计划、revision 和动作生成 UUID；
11. 生成服务端计划、revision 和动作 ID；
12. 原子保存计划 revision、动作和审计事件。

任何一步失败时整份候选不进入 `proposed`，只保存解析失败原因码、模型标识和 Prompt 策略版本，不保存可能包含敏感内容的原始模型输出，也不为失败候选额外计算哈希。

### 12.4 计划领域对象

`ResponsePlan`：

- `id`、`tenant_id`、`case_id`、`run_id`；
- `status` 和 `current_revision`；
- `created_by_role=response_planning`；
- `created_at`、`updated_at`。

`ResponsePlanRevision`：

- `id`、`plan_id`、`revision`、`parent_revision`；
- `public_summary`、`assumptions`、`stop_conditions`、`operator_notes`；
- `reason_code`、`model_id`、`prompt_policy_version` 和 `created_at`。

`ResponsePlanAction`：

- `id`、`plan_revision_id`、稳定顺序和依赖 ID；
- `tool_name`、`tool_version`、服务器解析的 target type/identifier；
- allowlist arguments、expected state、rollback strategy；
- evidence references、verification tool/version；
- server-assessed risk 和 approval requirement；
- action status、created_at。

### 12.5 计划状态机

```text
draft
  ├─ compilation_failed ─► needs_review
  └─ compiled ─► proposed
                   ├─ operator_rejected ─► rejected
                   ├─ no_change_actions ─► completed_advisory
                   └─ accepted ─► awaiting_execution
                                      ├─ executing
                                      ├─ verifying
                                      ├─ replanning ─► proposed（新 revision）
                                      ├─ needs_review
                                      ├─ cancelled
                                      └─ completed
```

状态只前进，重规划通过新 revision 表示，不能覆盖历史计划。计划接受不等于工具审批，动作仍逐个进入可信工具网关。

### 12.6 与可信工具调用的映射

- 每个可执行动作最多生成一个活动 `TrustedToolCall`；
- 调用保存 `plan_id`、`plan_revision_id` 和 `plan_action_id`；
- 幂等键由 tenant、run、plan action、tool version 和规范化参数摘要生成；
- 计划的建议 risk 不参与策略，可信网关重新评估；
- 工具参数或证据改变必须先生成新计划 revision；
- 一个动作审批不能授权同计划中的其他动作；
- 依赖动作未验证成功时，后续动作不能发放执行租约；
- 只读前置查询可以自动执行，但必须审计并消耗工具预算。

## 13. 安全闭环详细流程

### 13.1 主流程

1. 创建通用 `AgentRun` 和当前运营任务输入；
2. 固定本次运行的 Agent Tool Catalog revision；
3. 总控和专业角色调用获授权的只读工具形成结构化观察；
4. 响应规划角色产生候选计划；
5. 服务端编译、重绑定并保存计划；
6. 没有可执行动作时生成建议报告并结束为 `completed_advisory`；
7. 有可执行动作时进入可信工具策略；
8. 策略拒绝则保存原因并转人工，不让模型改写策略；
9. 需要审批时等待绑定请求摘要的审批；
10. 获批后获取执行租约并调用固定 Adapter；
11. 保存执行尝试，结果未知时不重放；
12. 调用配对只读验证器或等待新遥测；
13. 把验证结果和证据引用转换为 `ReactObservation`；
14. 分类器给出固定失败类别；
15. 决策器选择完成、查询状态、只读重试、重规划或人工接管；
16. 重规划只生成新 proposed action，再次经过完整策略、审批、幂等和验证；
17. 只有所有必需动作验证成功才结束为 `completed`；
18. 报告区分已确认事实、知识依据、计划建议、已审批动作、实际执行、验证结果和未知项。

### 13.2 决策矩阵

| 观察 | 允许的自动决策 | 禁止行为 |
| --- | --- | --- |
| 只读工具明确失败 | 在工具定义和预算允许时有限重试，否则转人工 | 把失败当空结果 |
| 变更工具结果未知 | 调用配对状态查询 | 重放变更动作或宣称未执行 |
| 执行明确失败且目标未改变 | 在白名单候选中生成新计划 revision | 直接切换任意工具 |
| 验证失败 | 重规划或人工复核 | 把 Adapter succeeded 当最终成功 |
| 验证无法判断 | 查询新遥测或人工复核 | 猜测最终状态 |
| 审批拒绝 | 人工复核或结束 | 自动换参数规避审批 |
| 紧急停止/自动化关闭 | 停止发新租约并转人工 | 自动恢复或伪称撤回在途动作 |
| 证据不足/冲突 | 补充只读证据或转人工 | 生成高风险动作 |
| 预算耗尽/重复循环 | 停止并转人工 | 通过新会话重置预算 |
| 全部必需动作验证成功 | 完成并生成报告 | 省略验证引用 |

### 13.3 预算

预算由服务端拥有并在发起新角色、模型调用、MCP 调用或可信工具调用前投影：

- 角色步骤；
- ReAct 循环；
- 墙钟时间；
- Token；
- 模型费用；
- Agent Tool 调用；
- 外部 MCP 调用；
- 可信变更工具调用；
- 计划 revision 数；
- 单动作验证次数。

外部 MCP 限额、角色限额和全局限额取最小值。预算消耗与 loop CAS 同事务提交，客户端提供的计数一律忽略。

### 13.4 恢复和并发

- `AgentRun`、`ResponsePlan`、`TrustedToolCall` 和 `ReactLoop` 都使用 revision/CAS；
- 计划、审批、执行尝试、验证、观察和决策使用只追加记录；
- worker 恢复先读取可信工具租约和调用状态，再决定查询、验证或人工复核；
- 同一 revision 多 worker 竞争时最多一个提交成功；失败方重读，不重复调用；
- MCP 2026-07-28 无协议 session，跨请求状态使用数据库中的显式 run/plan/call ID，并验证主体绑定；
- 进程关闭不把在途变更动作标为失败，恢复后先查询状态；
- 外部 MCP 只读调用在网络断开后可按定义有限重试，但每次尝试单独审计。

## 14. 通用运行模型与数据库迁移

### 14.1 为什么需要 `agent_runs`

当前 `investigation_runs` 必须关联早期仿真 incident 和 simulation instance，不能表达“按时间窗口生成安全运营报告”。阶段 4～6 表又通过外键依赖它。直接为当前运营报告伪造仿真事件会污染事实边界，因此必须建立通用父运行表。

### 14.2 迁移 1：通用运行父表

新增 `agent_runs`：

- `id`、`tenant_id` 复合唯一；
- `principal_id`；
- `run_kind`：`incident_investigation` 或 `operations_report`；
- `status`：`pending`、`running`、`awaiting_approval`、`awaiting_execution`、`verifying`、`needs_review`、`completed`、`failed`、`cancelled`；
- `goal`、`catalog_revision`、`revision`；
- `created_at`、`updated_at`、`completed_at`。

迁移步骤：

1. 创建 `agent_runs`；
2. 为所有现有 `investigation_runs` 回填父行，保持相同 id 和 tenant；
3. 给 `investigation_runs(id, tenant_id)` 增加到 `agent_runs` 的复合外键；
4. 将 `case_contexts`、agent private context、handoff、execution、`trusted_tool_calls` 和 `react_loops` 的 run 外键改指向 `agent_runs`；
5. SQLite 使用建新表、复制、校验行数和重命名方式重建；
6. 升级、降级、再次升级后逐表验证外键、唯一约束、索引和数据摘要。

不得删除 `investigation_runs`，以保留旧仿真历史和兼容 API。

### 14.3 迁移 2：运营运行和报告关联

新增 `operations_runs`：

- `run_id`、`tenant_id`，外键到 `agent_runs`；
- `start_at`、`end_at`；
- `report_id` 可空且唯一；
- `created_at`。

新生成报告必须包含 UUID `run_id`。历史 JSON 报告保持只读兼容并显示 `legacy_without_run`，不伪造工具或闭环轨迹。提供显式离线导入命令时，只导入能够验证字段和时间范围的报告；导入不会生成不存在的智能体轨迹。

### 14.4 迁移 3：Agent Tool 与 MCP

新增：

`agent_tool_calls`：

- tenant、principal、run/case、role；
- direction：`internal`、`mcp_inbound`、`mcp_outbound`；
- provider kind/id、tool identity/alias、catalog/schema revision；
- 参数公开投影；
- status、reason code、result count、公开摘要、引用；
- duration、attempt、bytes read、truncated；
- request ID、created/finished time。

`mcp_peer_snapshots`：

- peer ID、协议版本、server info 公共摘要；
- catalog revision、工具数量、发现时间、过期时间；
- 状态和稳定错误码；
- 不保存 endpoint 凭据、Token 或原始 tools/list body。

`mcp_tool_snapshots`：

- peer snapshot、remote name、本地 alias；
- input/output Schema 及摘要；
- 本地 classification、allowed roles、enabled；
- 远端 annotations 仅保存安全裁剪后的对照字段。

### 14.5 迁移 4：响应计划

新增 `response_plans`、`response_plan_revisions`、`response_plan_actions` 和 `response_plan_events`。所有表都带 tenant 复合外键和必要唯一约束。

现有 `trusted_tool_calls.plan_id` 若存在历史数据：

1. 按 tenant、run、case、plan ID 创建 `legacy_imported` 计划；
2. 计划只记录“历史调用关联”，不反向推断模型候选或审批原因；
3. 新增 `plan_revision_id`、`plan_action_id` 可空字段；
4. 新调用必须非空，历史行保持空并在公开 API 标记 legacy；
5. 最后增加 plan 复合外键和热路径索引。

### 14.6 数据库约束

- 所有跨边界引用使用 `(id, tenant_id)` 复合外键；
- 状态和风险使用 CheckConstraint；
- revision、attempt、sequence 非负且有上界；
- JSON 字段在领域层验证类型、键集合、长度和总大小；
- idempotency、plan revision、action order 和 tool snapshot revision 使用唯一约束；
- 调用、观察、事件、审批、尝试和验证按 run/time 建索引；
- 迁移不能依赖 SQLite 关闭外键后静默丢数据，复制前后必须验证数量和摘要。

## 15. REST API 与 MCP API 边界

### 15.1 标准 MCP

```text
POST /mcp
```

完全遵循 MCP，不包装成 `/api/v1` 风格，也不返回项目 REST `ApiError` 结构。

### 15.2 只读 MCP 管理状态

在真实管理员 RBAC 完成前，REST 只提供只读状态：

```text
GET /api/v1/mcp/status
GET /api/v1/mcp/tools
GET /api/v1/mcp/peers
GET /api/v1/mcp/runs/{run_id}/calls
```

不提供通过 HTTP 添加 endpoint、上传 Token、修改网络策略或接受 Schema 变化的接口。配置变化通过受控文件、环境 Secret、代码评审和服务重启完成。

### 15.3 响应计划

```text
GET  /api/v1/response-plans/runs/{run_id}
GET  /api/v1/response-plans/{plan_id}
POST /api/v1/response-plans/{plan_id}/accept
POST /api/v1/response-plans/{plan_id}/reject
```

- tenant、principal 和角色来自认证边界；
- accept 只表示允许计划进入逐动作策略，不等于工具审批；
- reject/accept 需要 request ID、当前 revision 和原因；
- 并发 revision 不匹配返回 409；
- HTTP 不能提交新的 tool、risk、arguments、approval 或 policy 字段。

### 15.4 当前 API 兼容

- `/api/v1/operations/reports` 响应增加 `run_id` 和 `response_plan_summary`，前端先兼容字段可空；
- `/api/v1/tools/runs/{run_id}/calls` 继续返回可信变更工具轨迹；
- `/api/v1/react/runs/{run_id}/trajectory` 继续返回闭环轨迹；
- Agent Tool/MCP 调用使用新的 `/api/v1/mcp/runs/{run_id}/calls`，避免与可信工具混淆；
- 旧报告无 run ID 时不请求不存在的工具或 ReAct 轨迹。

## 16. 前端改造

### 16.1 安全运营报告页

增加：

- run ID 和运行状态；
- 本次固定工具目录摘要；
- 每次 Agent Tool 的来源标签：内置、RAG、外部 MCP；
- succeeded、empty、failed、timed_out、rejected 的不同状态；
- 响应计划公共摘要、动作依赖、证据、风险、审批要求和验证条件；
- “建议”与“已经执行/验证”明确分栏；
- 进入处置中心和 ReAct 轨迹的链接。

### 16.2 智能体与 ReAct 工作台

增加：

- 计划 revision 和动作 ID；
- MCP catalog revision 和工具选择原因；
- 工具回执与新遥测的引用；
- 查询状态、只读重试、重规划、人工接管的原因码；
- 计划旧/新差异，不展示原始模型输出。

### 16.3 处置中心

增加：

- 响应计划 → 计划动作 → 可信调用的映射；
- 计划接受与工具审批的区别提示；
- 执行结果、验证结果和未知状态；
- MCP 只读调用与可信变更调用的视觉区分；
- 紧急停止说明：只阻止未发出的新租约，不能撤回已进入外部系统的动作。

### 16.4 MCP 状态页

在现有状态或帮助页面增加只读信息：

- Server 启用状态、协议版本、鉴权模式、已发布工具数；
- 外部 peer 的公共 ID、协议版本、目录摘要、最近发现时间和健康状态；
- 不显示 endpoint 私有路径、Token、client secret、内部 IP 或原始错误。

所有响应继续执行运行时结构校验；不能只用 TypeScript 类型断言信任后端。

## 17. 配置设计

`Settings` 增加以下配置并设置边界：

```text
MCP_SERVER_ENABLED=false
MCP_SERVER_PATH=/mcp
MCP_PROTOCOL_VERSION=2026-07-28
MCP_ALLOWED_ORIGINS=[]
MCP_AUTH_MODE=disabled
MCP_AUTH_ISSUER=
MCP_AUTH_AUDIENCE=
MCP_AUTH_JWKS_URL=
MCP_REQUIRED_SCOPE_PREFIX=shieldchain
MCP_REMOTE_CONFIG_PATH=
MCP_CATALOG_REFRESH_SECONDS=300
MCP_CONNECT_TIMEOUT_SECONDS=5
MCP_CALL_TIMEOUT_SECONDS=30
MCP_MAX_REQUEST_BYTES=262144
MCP_MAX_RAW_RESPONSE_BYTES=2097152
MCP_MAX_PUBLIC_RESULT_BYTES=65536
MCP_MAX_REMOTE_TOOLS=100
MCP_MAX_REMOTE_SCHEMA_BYTES=65536
MCP_MAX_EXTERNAL_CALLS_PER_RUN=10
MCP_PEER_CONCURRENCY=4
MCP_CIRCUIT_FAILURE_THRESHOLD=5
MCP_CIRCUIT_OPEN_SECONDS=60
RUN_LIVE_MCP_TEST=0
LIVE_MCP_CALL_LIMIT=0
```

生产校验：

- Server 启用必须 `MCP_AUTH_MODE=oauth`；
- issuer、audience、JWKS URL 和非空 allowed origins 必须同时存在；
- JWKS 和 issuer 必须 HTTPS；
- remote config 文件不存在、权限不安全或包含未知字段时，外部 Client 子系统关闭并报告明确错误；
- 所有限额有硬上界且不能为负；
- `.env.example` 只给安全默认值，不包含真实 endpoint 或 Secret；
- Compose 默认不启用 MCP 网络入口；服务器覆盖配置显式启用。

## 18. 威胁模型和验证要求

| 威胁 | 必须实施的控制 | 必须有的测试 |
| --- | --- | --- |
| 未认证调用 | OAuth Resource Server、scope、默认关闭 | 无 Token、错 issuer、错 audience、过期、scope 不足 |
| 跨租户访问 | 服务端 Authority、复合外键、SQL tenant 条件 | 猜测 run/call/plan/handle 均返回不存在 |
| DNS rebinding/SSRF | Origin、Host、DNS/IP 策略、禁止重定向 | loopback、link-local、私网、元数据、DNS 切换 |
| Token passthrough | peer 独立凭据和 audience | 入站 Token 不出现在远端请求或日志 |
| 工具目录投毒 | 管理员映射、显式 Schema revision、运行固定快照 | 远端改名、改 Schema、增加工具、恶意描述 |
| Prompt 注入 | 工具结果不可信包络、输出裁剪、系统规则优先 | 结果要求泄密、改权限、调用未授权工具 |
| 参数注入 | JSON Schema、具体类型、additionalProperties=false | Shell、URL、SQL、超长、额外字段、Unicode 边界 |
| 结果炸弹 | 流式读取上限、条目/深度/字符串限制 | 巨大 JSON、深嵌套、无限 SSE、压缩异常 |
| 混淆代理 | issuer/audience/resource、独立客户端 | 错授权服务器、错资源 Token、开放重定向 |
| 状态 handle 劫持 | 随机 handle、主体绑定、TTL | 猜测、重放、跨主体、过期 handle |
| 审批重放 | 请求摘要、策略版本、有效期、参数变化失效 | 同审批改参数/目标/工具版本 |
| 重复变更 | 幂等、租约、结果未知先查询 | 并发 worker、超时、进程崩溃恢复 |
| 虚假成功 | 执行后验证和新遥测引用 | Adapter success 但目标状态未改变 |
| 循环失控 | 预算、观察指纹、最大 revision | 重复观察、模型反复换措辞、预算边界 |
| 敏感信息泄漏 | allowlist 投影、日志过滤、前端校验 | Token、Prompt、原始载荷、内部 URL 和堆栈扫描 |

## 19. 测试与验收矩阵

### 19.1 单元测试

- Agent Tool 定义、目录排序、目录 revision、权限交集；
- 四类内置工具输入/输出 Schema 和租户过滤；
- MCP peer 配置、URL、DNS、TLS、Origin 和重定向策略；
- 远端工具名称映射、Schema 大小/结构变化和 annotation 不可信；
- 响应计划候选 Schema、依赖图、证据重绑定和计划编译；
- 计划状态机、revision、摘要和幂等键；
- 失败分类、重新规划、预算和循环检测；
- 公开投影和敏感字段过滤。

### 19.2 集成测试

- 官方 SDK Client 对 `/mcp` 完成发现、`tools/list` 和四类 `tools/call`；
- 2026-07-28 请求头和 `_meta` 一致性；
- SDK v2 对 2025-11-25 兼容路径；
- OAuth/JWKS 测试替身、scope、tenant 映射；
- 受控外部 MCP Server 测试替身的发现、固定、调用和熔断；
- Agent Tool 调用审计持久化；
- 通用 `agent_runs` 及旧 investigation 数据回填；
- 响应计划到可信工具调用的关联；
- 迁移 upgrade → downgrade → upgrade；
- Nginx `/mcp` JSON 与请求范围 SSE 代理合同。

### 19.3 端到端 smoke

至少覆盖：

1. 创建当前运营运行；
2. 智能体选择内置或测试外部只读工具；
3. 生成带证据响应计划；
4. 计划编译并进入策略；
5. 测试仿真变更动作等待审批；
6. 审批后幂等执行；
7. 配对查询生成新观察；
8. 验证成功并完成报告；
9. 前端能看到 run、plan、call、verification 和 ReAct 轨迹；
10. 全链路不出现私有字段。

失败 smoke 至少覆盖：

- MCP 无认证、Origin 错误、Schema 改变；
- 外部工具超时和熔断；
- 只读失败不变成 empty；
- 响应计划引用跨租户证据；
- 审批拒绝；
- 变更结果未知后只查询不重放；
- 验证失败后生成新 revision；
- 重复观察触发 loop detected；
- 预算耗尽和人工接管；
- 紧急停止期间不发新租约。

### 19.4 MCP 一致性

- 使用官方 MCP conformance 工具或 SDK 提供的等价官方测试；
- 保存工具版本、协议版本、命令、环境和完整结果摘要；
- 不允许以手写 HTTP 200 smoke 代替协议一致性；
- 一致性测试失败不能通过关闭相关规范检查或伪造响应解决；
- 官方 SDK 已知缺口必须在验收报告中逐项记录影响和缓解，不得笼统写“兼容 MCP”。

### 19.5 实时验收

真实外部平台只在以下条件同时满足时测试：

- 获得书面授权和测试窗口；
- endpoint、scope、数据范围和调用上限确认；
- 使用测试 tenant/资产；
- 默认只读；
- 日志和报告脱敏；
- 有停止条件和联系人；
- 真实调用次数通过 `LIVE_MCP_CALL_LIMIT` 设置硬上限；
- 结果明确标记测试环境，不外推为生产商用验收。

## 20. 分阶段实施任务

每个 Task 都必须先写或更新测试，再做最小实现，运行聚焦验证，审查 diff，更新开发日志并形成独立 Git commit。不得把全部功能压成一个提交。

### Task 0：基线锁定与协议 Spike

> 状态：已完成（2026-08-22）。官方 MCP Python SDK 2.0.0 在项目 Python 3.12 测试环境中协商到协议 `2026-07-28`，内存 `tools/list`、`tools/call` 和现有运营工具回归通过。

目标：确认官方 SDK v2 与当前 Python/FastAPI/Starlette 组合可用，锁定当前行为。

修改：

- `backend/pyproject.toml` 增加 `mcp>=2,<3`；
- 新增最小 in-process MCP 测试，不接业务数据库；
- 记录实际解析版本和官方一致性工具版本；
- 为当前四类 façade 和运营报告补行为快照测试。

验收：

- 2026-07-28 tools/list/call 最小测试通过；
- 2025-11-25 SDK 兼容测试通过或得到可复现、明确的阻断结论；
- 当前运营报告测试无回归。

建议提交：`test: establish mcp protocol compatibility baseline`

### Task 1：协议无关 Agent Tool 合同

> 状态：已完成（2026-08-22）。复用现有 `operations` 模块完成协议去耦命名，没有新增架构包、数据库或配置层。

目标：让 `operations/react_collaboration.py` 和 `operations/mcp_tools.py` 中的现有内部工具合同使用协议无关名称，同时保持当前行为和兼容入口。

修改：

- 在现有 `mcp_tools.py` 增加协议无关 `ReadOnlyAgentTool` 和 `standard_agent_tools`；
- 在现有 `react_collaboration.py` 将 Broker 和目录改为协议无关公开名称；
- 服务和测试切换到新名称；
- 保留旧 `ReadOnlyMcpTool`、`standard_mcp_tools` 直接别名，避免现有调用方立即中断。

验收：

- 现有角色白名单、工具选择、单运行缓存和安全降级行为保持；
- MCP 协议基线、运营工具单元测试和运营报告 API 测试通过；
- 修改文件 Ruff 通过。

建议提交：`feat: add protocol independent agent tool contracts`

### Task 2：迁移四类内置 Provider 与 Broker

目标：在标准 MCP Server 接线前，为现有四类 Provider 和 Broker 补齐网络边界真正需要的输入校验与稳定失败结果；不移动文件、不复制查询实现。

修改：

- 复用 `operations/mcp_tools.py` 和 `AgentToolBroker`；
- 增加统一时间范围校验，明确 failed、empty 和 succeeded；
- 保持现有单运行缓存和 API 输出兼容；
- 只增加标准 MCP Server 调用所必需的错误边界，不提前实现持久化、远端 Client 或复杂预算。

验收：

- 四类查询结果和证据限制不倒退；
- failed、empty 明确区分；
- 同工具单运行只执行一次；
- 跨租户和额外字段测试通过。

建议提交：`refactor: route operations tools through agent tool broker`

### Task 3：通用 Agent Run 迁移

目标：解除当前闭环模型对退役仿真 `investigation_runs` 的独占依赖。

修改：

- 新增 `agent_runs` 和 `operations_runs`；
- 回填历史 investigation 父行；
- 重建阶段 4～6 run 外键；
- 当前运营报告创建 run ID；
- 历史报告显式 legacy 降级。

验收：

- 迁移升降升；
- 历史行数和摘要一致；
- 旧调查 API 回归；
- 新运营 run 可创建 case context、tool 和 react 子记录。

建议提交：`feat: introduce generic agent run persistence`

### Task 4：Agent Tool 调用审计

目标：内部、入站 MCP 和出站 MCP 使用同一公开审计合同。

修改：

- 新增 `agent_tool_calls` 表、仓储和 API 投影；
- Broker 原子记录调用开始和终态；
- 增加 request ID、catalog revision、耗时、大小和截断；
- 不保存原始载荷。

验收：

- 三种 direction 测试；
- 崩溃后 running 调用恢复为明确未知/失败状态；
- 敏感字段扫描通过。

建议提交：`feat: persist bounded agent tool call audits`

### Task 5：标准 MCP Server

目标：通过 `/mcp` 标准发布四类只读工具。

修改：

- 新增 `mcp/server.py`、`mount.py`、`authority.py`；
- tools/list 和 tools/call 适配 Broker；
- FastAPI 生命周期和路由挂载；
- 配置默认关闭；
- 协议错误与工具错误分层。

验收：

- 官方 Client 可发现和调用；
- 工具目录稳定；
- 无 MCP Session 依赖；
- 内部智能体未走本机 HTTP。

建议提交：`feat: expose read only security tools over mcp`

### Task 6：MCP 入站鉴权与传输加固

目标：在网络暴露前完成生产安全边界。

修改：

- OAuth/JWT Resource Server 验证；
- Protected Resource Metadata；
- Origin、Host、请求大小和速率限制；
- Settings 生产校验；
- Nginx `/mcp` 代理；
- 日志脱敏。

验收：

- 认证和 scope 矩阵；
- DNS rebinding Origin 测试；
- production 缺配置启动失败；
- JSON 和请求范围 SSE 都能通过反向代理。

建议提交：`feat: secure mcp server transport and authorization`

### Task 7：外部 MCP 配置、发现与快照

目标：只从管理员固定配置发现获批准的外部只读工具。

修改：

- `peer_config.py`、`transport_security.py`、`discovery.py`；
- example YAML；
- `mcp_peer_snapshots`、`mcp_tool_snapshots`；
- Schema revision、结构变化检测和过期策略；
- SSRF/TLS/DNS/redirect 防护。

验收：

- 任意 URL、私网、重定向和 Schema 变化测试；
- 未映射远端工具不可见；
- 远端 annotation 不改变分类；
- 凭据不持久化。

建议提交：`feat: add allowlisted mcp peer discovery snapshots`

### Task 8：受控外部 MCP Provider

目标：让获批准的外部只读工具进入统一 Broker。

修改：

- `mcp/client.py`、`remote_provider.py`；
- timeout、大小、并发、速率和熔断；
- 远端结果不可信解析和裁剪；
- 目录 revision 固定到 run；
- 独立凭据和 Token 缓存。

验收：

- 测试 Server 调用成功；
- 超时、巨大结果、无效 structured content、断流和熔断；
- 入站 Token 不透传；
- 外部变更工具默认拒绝。

建议提交：`feat: call approved external mcp read tools safely`

### Task 9：响应计划领域、Schema 与持久化

目标：替换自然语言动作和松散 `proposed:` 字符串。

修改：

- 新增 `response_planning/` 领域、candidate Schema、编译器；
- 新增计划四表和迁移；
- 历史 tool plan ID 安全回填；
- 单元和仓储测试。

验收：

- 证据、工具、参数、依赖图、revision 和状态机测试；
- 模型不能注入风险、审批、tenant、URL、Shell 或代码；
- 原子保存和跨租户拒绝。

建议提交：`feat: add compiled and versioned response plans`

### Task 10：响应规划智能体接线

目标：当前运营报告的响应规划角色真实产出严格计划。

修改：

- 提供严格输出 Schema 和最小上下文；
- 实现模型解析失败的确定性建议降级；
- 将角色公开摘要与 plan ID 关联；
- 报告区分建议与执行事实。

验收：

- 合法计划、无动作建议、无效 JSON、未知工具、跨案证据和模型不可用；
- 不保存思维链或原始 Prompt；
- 响应角色仍不持有 Adapter。

建议提交：`feat: generate strict response plans from operations runs`

### Task 11：计划到可信工具网关

目标：逐动作编译可信请求，并保持审批和工具边界。

修改：

- 增加 plan revision/action 到 `TrustedToolCall` 的关联；
- 依赖动作门禁；
- 请求摘要和幂等键；
- 计划 accept/reject API；
- 继续使用现有 registry、policy、approval、execution 和 verification。

验收：

- plan accept 不等于 tool approval；
- 参数变化使审批失效；
- 依赖未验证不能执行；
- 并发调用最多一个租约。

建议提交：`feat: compile response actions into trusted tool calls`

### Task 12：真实安全闭环编排

目标：把工具回执、新观察、验证和重规划接入当前运营 run。

修改：

- 当前 run 创建/恢复 `ReactLoop`；
- TrustedToolCall/Verification 转 Observation；
- 查询状态、只读重试、重规划和人工接管调度；
- 最终报告读取闭环事实；
- 服务重启恢复扫描。

验收：

- 成功闭环和全部失败矩阵；
- 结果未知不重放；
- 验证失败生成新 plan revision；
- 预算/循环/紧急停止生效。

建议提交：`feat: close the response verification and replanning loop`

### Task 13：REST 与前端公开工作台

目标：让用户能核验工具、计划和闭环，而不泄漏私有内容。

修改：

- MCP 状态/目录/调用只读 API；
- 响应计划查询和控制 API；
- 运营报告、智能体/ReAct、处置中心页面；
- 运行时响应校验和安全渲染测试。

验收：

- 加载、错误、空、legacy、超时、部分数据和取消状态；
- 不渲染 Token、Prompt、endpoint 私有路径、原始载荷或堆栈；
- 页面明确“建议/批准/执行/验证”差别。

建议提交：`feat: show mcp plans and safety loop projections`

### Task 14：一致性、安全门禁和交付

目标：形成可复现验收和部署/回滚材料。

修改：

- MCP conformance 脚本；
- Phase smoke 和安全合同；
- `verify.ps1`、Compose、Nginx、`.env.example`；
- README、架构、测试、部署、运维和开发日志；
- 实际测试报告。

验收：

- 全量门禁；
- 临时数据库迁移往返；
- 容器只读、安全上下文和健康检查；
- 本地和服务器部署演练；
- 回滚演练；
- 未测试真实设备仍明确标记未实现。

建议提交：`test: gate mcp response planning and safety loop delivery`

## 21. Git 项目管理规则

### 21.1 分支

实际功能开发从本文档评审完成的提交创建。本文档当前使用的独立分支为 `codex/mcp-agent-tools-execution-doc`：

```bash
git switch codex/mcp-agent-tools-execution-doc
git status --short --branch
git switch -c codex/mcp-agent-safety-loop
```

如果本文已经合并到正式基线，则直接从包含本文的合并提交创建功能分支，并在开发日志记录基线 commit。不得在脏工作区切换或重写用户改动。

### 21.2 提交

- 一个 Task 可以拆成多个小提交，但一个提交只完成一个可验证目的；
- 优先顺序为测试/合同、领域实现、接线、文档；
- 使用 `feat:`、`fix:`、`test:`、`refactor:`、`docs:`；
- 迁移和对应仓储不能分散到不可运行的长期中间状态；
- 不提交 `.env`、实际 MCP 配置、Token、数据库、测试真实载荷或私有证书；
- 每次提交前运行聚焦测试并检查 `git diff --check`；
- 每个 Task 完成后更新当日开发日志；
- 未经明确要求不 force push、不改写共享历史、不删除远端分支。

### 21.3 合并门禁

合并前必须：

1. 工作区只有预期变更；
2. 每个迁移可升、可降、可再升；
3. 聚焦测试和全量测试有真实记录；
4. 协议和安全评审完成；
5. 文档状态与代码一致；
6. README 不再把内部 façade 误写成完整标准 MCP；
7. 真实平台未验收时仍保持“部分实现”；
8. 至少一名评审者检查权限、Token、SSRF、工具分类和结果未知分支。

## 22. 验证命令

实现后至少运行：

```powershell
conda run -n ShieldChain python -m ruff check backend
conda run -n ShieldChain python -m pytest backend/tests/unit/agent_tools -q
conda run -n ShieldChain python -m pytest backend/tests/unit/mcp -q
conda run -n ShieldChain python -m pytest backend/tests/unit/response_planning -q
conda run -n ShieldChain python -m pytest backend/tests/integration/mcp -q
conda run -n ShieldChain python -m pytest backend/tests/integration/response_planning -q
conda run -n ShieldChain python -m pytest backend/tests/integration/react -q
conda run -n ShieldChain python -m pytest backend/tests/integration/tools -q
conda run -n ShieldChain python -m pytest backend/tests -q
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
npm run lint --prefix frontend
npm run build --prefix frontend
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml -f compose.server.yaml config --quiet
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify.ps1
```

迁移使用临时数据库：

```powershell
$env:DATABASE_URL = "sqlite:///./data/mcp-safety-loop-migration-test.db"
conda run -n ShieldChain python -m alembic -c backend/alembic.ini upgrade head
conda run -n ShieldChain python -m alembic -c backend/alembic.ini downgrade -1
conda run -n ShieldChain python -m alembic -c backend/alembic.ini upgrade head
```

开发者不得用仓库正式数据库做降级测试。测试脚本必须创建并验证专用临时路径后再清理。

## 23. 上线顺序

采用默认关闭、逐层放量：

1. 部署数据库和协议无关 Agent Tool 重构，MCP Server/Client 均关闭；
2. 验证当前运营报告行为无回归；
3. 在测试环境启用 `/mcp`，只允许测试 IdP 和四类只读工具；
4. 完成官方 Client 与一致性测试；
5. 在测试环境启用一个本地测试外部 MCP peer；
6. 启用响应计划，只展示不执行；
7. 启用仿真可信工具和人工审批闭环；
8. 验证失败、恢复和紧急停止；
9. 在获授权环境接入真实外部只读 MCP；
10. 真实变更设备继续保持关闭，直到单独完成 Adapter、审批、验证和回滚验收。

每一步至少观察一个完整测试周期；出现跨租户、Token 泄漏、目录漂移、虚假成功、重复变更或无法停止时立即回滚并停止后续放量。

## 24. 回滚方案

### 24.1 功能回滚

1. 设置 `MCP_SERVER_ENABLED=false`；
2. 移除或禁用 `MCP_REMOTE_CONFIG_PATH` 中的 peers；
3. 关闭自动化控制，触发可信工具全局停止；
4. 保留已有调用、计划、审批、执行和验证审计；
5. 当前报告退回内置 Agent Tool 和保守建议路径；
6. 前端对新 API 404/不可用显示明确降级，不恢复虚假数据。

### 24.2 版本回滚

- 先停止新运行和新工具租约；
- 等待只读调用 deadline，检查在途变更工具状态；
- 对结果未知动作先查询，不直接回滚应用；
- 使用已验证的上一镜像和匹配配置；
- 只有确认新表没有必须保留的新审计时才执行数据库 downgrade；
- 若已有新审计数据，保留向前兼容数据库，只回滚应用功能开关；
- 回滚后运行健康、报告、MCP 关闭状态、工具控制和数据完整性检查。

### 24.3 不可做的回滚

- 不删除或覆盖调用、审批、尝试、验证、计划 revision 和人工控制记录；
- 不通过重置数据库伪装动作未执行；
- 不撤销已经到达外部设备的动作而不先确认当前状态；
- 不在共享服务器终止其他用户进程；
- 不把生产 Token 复制到本地排障。

## 25. 交付物

本阶段最终必须交付：

- 标准 MCP Server 和受控 MCP Client 源码；
- 统一 Agent Tool 与响应计划源码；
- 通用运行、MCP、调用审计和响应计划迁移；
- REST API、前端工作台和安全公开投影；
- 官方一致性、单元、集成、前端、迁移、容器和 smoke 测试；
- `config/mcp/servers.example.yaml` 和 `.env.example`；
- MCP 本地开发、生产部署、外部 peer 接入、密钥轮换、故障排查和回滚手册；
- 实际测试报告和当日开发日志；
- README 的准确能力矩阵；
- Git 分支、分阶段提交和最终评审记录。

## 26. 设计决策摘要

| 决策 | 选择 | 原因 |
| --- | --- | --- |
| 主协议 | MCP `2026-07-28` | 当前稳定规范，无协议级 session，适合普通负载均衡和标准头路由 |
| SDK | 官方 Python SDK v2 | 避免自行实现 JSON-RPC、协议协商和版本兼容 |
| 传输 | Streamable HTTP | 适合当前容器/服务器部署；旧 HTTP+SSE 不再新增 |
| stdio | 第一版禁止 | 服务端拉起任意子进程与本项目安全边界冲突 |
| MCP 能力 | 仅 Tools | 当前需求集中在工具；避免扩展未使用攻击面 |
| 内部调用 | 直接 Agent Tool Provider | 避免本机 HTTP 回环、身份混淆和额外故障 |
| 外部工具 | 管理员逐项映射、默认只读 | 远端声明不能成为本地授权事实 |
| 变更工具 | 继续走本地可信网关 | 保留策略、审批、幂等、租约和验证边界 |
| 响应规划 | 严格候选 Schema + 服务端编译 | 模型建议不等于可执行请求 |
| 当前运行 | 新增通用 `agent_runs` | 不能用退役仿真 incident 伪造当前运营任务 |
| MCP 配置 | 文件和 Secret 引用，REST 只读 | 当前没有真实管理员 RBAC，不能安全开放动态写控制面 |
| 目录变化 | 新运行生效，旧运行固定 revision | 保证恢复、审计和结果可复现，不引入额外哈希计算 |
| 成功判据 | 新遥测与执行后验证 | Adapter 返回成功不能证明安全状态已改变 |
| 自动化 | 默认关闭、逐层放量 | 先验证只读、计划和仿真，再评审真实设备 |

本文评审通过后，开发从 Task 0 开始；不得跳过协议 Spike、通用运行迁移、响应计划编译或安全测试，直接把现有 Python façade 对外命名为标准 MCP。
