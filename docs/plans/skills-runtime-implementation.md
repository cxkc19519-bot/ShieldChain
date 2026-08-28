# ShieldChain 可安装 Skills 运行时实施方案

> 文档状态：待实施设计（2026-08-21）。本文定义 ShieldChain 第一版 Skills（技能包）运行时的产品边界、包格式、安装流程、安全模型、后端与前端改造、测试和分阶段验收。实现过程中若修改本设计，必须同步记录原因、替代方案和迁移影响。

## 1. 背景与目标

ShieldChain 当前使用固定的七类专业角色、硬编码职责提示、服务端工具白名单和本地 RAG。新增一种调查流程通常需要修改 Python 代码、提示词和测试后重新部署，无法像主流 Agent 一样快速安装可复用能力。

本阶段目标是增加一个**可安装、可审计、可禁用、可升级、默认安全**的 Skills 运行时，使管理员可以通过本地压缩包或受控 GitHub 来源安装 `SKILL.md` 技能包，并让智能体在任务运行时按角色和任务选择少量适用 Skill，作为低于系统规则和安全边界的过程指导。

第一版必须实现：

1. 使用 `SKILL.md` 加 YAML Front Matter（前置元数据）的兼容格式；
2. 支持上传本地 Skill 包和从受控 GitHub URL 安装；
3. 安装前预检、风险扫描、内容摘要、哈希锁定和人工确认；
4. Skill 版本持久化、启用、禁用、升级、回滚和卸载；
5. 按租户、角色、任务和 Token 预算筛选 Skill；
6. 在公开智能体轨迹中记录 Skill 名称、版本、哈希和选择原因；
7. Skill 只能提供过程指导，不能授予工具、数据、网络、凭据或处置权限；
8. 重启后 Skill 状态和版本保持；
9. 完整后端 API、前端管理页面、单元测试、安全测试和集成测试。

## 2. 非目标

第一版明确不实现：

- 不执行 Skill 包中的 Python、Shell、PowerShell、Node.js 或二进制程序；
- 不允许 Skill 安装依赖、运行包管理器或修改系统配置；
- 不允许 Skill 自行注册 MCP Server、HTTP 地址、数据库连接或任意工具；
- 不从任意公网地址下载内容，只允许 HTTPS GitHub 仓库/发布归档和管理员上传；
- 不自动更新 Skill；升级必须重新预检并由管理员确认；
- 不把 Skill 声明的角色、风险、权限或 `allowed-tools` 当作服务端授权事实；
- 不将知识库文档自动转换为 Skill；Knowledge、Skill 和 Tool 继续保持不同边界；
- 不允许模型安装、启用、升级或删除 Skill；这些是管理员控制面操作；
- 不在第一版建设公共 Skill 市场、评分系统、签名证书体系或付费分发；
- 不改变真实处置必须经过策略、审批、可信工具网关和执行后验证的要求。

## 3. 核心原则

### 3.1 三类能力严格分离

- **Knowledge（知识）**：描述事实、规范、历史和解释材料，通过 RAG 检索；
- **Skill（技能）**：描述执行某类任务时应遵循的步骤、检查点、停止条件和输出要求；
- **Tool（工具）**：由服务端注册并实际读取数据或改变状态的能力。

Skill 可以建议“查询告警”或“检索 ATT&CK”，但只能使用当前角色已经被服务端授权的工具。Skill 不能通过文字声明创造一个工具，也不能扩大现有工具权限。

### 3.2 权限只做交集，不做并集

运行时有效工具集合必须按下面的交集计算：

```text
effective_tools =
    role_allowed_tools
    ∩ server_policy_allowed_tools
    ∩ tenant_enabled_tools
    ∩ skill_requested_tools（若 Skill 有声明）
```

如果 Skill 未声明工具，仍以角色和服务端策略为准；如果 Skill 声明了未授权工具，该声明被忽略并产生公开安全原因码。任何情况下都不允许通过 Skill 做权限并集。

### 3.3 指令优先级固定

提示上下文顺序必须固定为：

1. 服务端系统规则；
2. 安全边界；
3. 当前角色职责与允许动作；
4. 当前任务和案件事实；
5. 管理员批准的 Skill 过程指导；
6. 证据、知识、工具结果和角色交接；
7. 输出 Schema。

Skill 不是系统提示词。Skill 中与第 1～3 项冲突的内容无效，且应被扫描器标记。

### 3.4 默认拒绝和可追溯

- 未安装、未启用、已隔离、版本不兼容或校验失败的 Skill 不进入候选集；
- 安装、启停、升级、回滚、卸载和运行时选择都必须写审计记录；
- 每次运行绑定确切 Skill 版本与 SHA-256，运行过程中不能静默切换版本；
- 错误必须显式降级，不能伪造 Skill 已加载或已执行。

## 4. Skill 包规范

### 4.1 目录结构

第一版支持目录或 `.zip` 包，根目录必须存在且只存在一个 `SKILL.md`：

```text
alert-triage/
├── SKILL.md
├── references/          # 可选，只读参考文档
│   └── severity-guide.md
├── templates/           # 可选，只读输出模板
│   └── triage-report.md
└── assets/              # 可选，不注入模型；仅供管理员查看
    └── workflow.svg
```

第一版允许的根目录内容：

- `SKILL.md`；
- `references/`；
- `templates/`；
- `assets/`。

第一版禁止：

- `scripts/`、可执行文件、动态库和包管理清单；
- 符号链接、硬链接、Windows reparse point；
- 绝对路径、`..`、隐藏路径跳转和大小写碰撞文件；
- 嵌套压缩包和加密压缩包；
- `.env`、私钥、数据库、PCAP、凭据文件和模型权重。

### 4.2 `SKILL.md` Front Matter

推荐格式：

```yaml
---
name: alert-triage
description: Use when prioritizing Wazuh alerts and review cases.
version: 1.0.0
author: ShieldChain Team
license: MIT
compatibility:
  shieldchain: ">=0.1.0,<0.2.0"
metadata:
  shieldchain:
    display_name: 告警分诊
    language: zh-CN
    tags: [wazuh, triage, soc]
    roles: [alert_triage, threat_investigation]
    requested_tools:
      - security.alerts.list
      - security.events.list
    max_context_tokens: 1800
    references:
      - references/severity-guide.md
    templates:
      - templates/triage-report.md
---
```

正文必须包含非空 Markdown。推荐结构：

```markdown
# 告警分诊

## 适用条件
## 不适用条件
## 输入要求
## 操作步骤
## 证据检查点
## 停止与人工接管条件
## 输出要求
## 常见错误
## 完成检查清单
```

### 4.3 字段规则与主流格式兼容

兼容导入的最低强制字段：

- `name`：小写字母、数字和连字符，长度 1～64；
- `description`：非空，最多 1024 字符，前部必须能说明触发条件；
- 正文：UTF-8，非空。

ShieldChain 原生包推荐提供 `version`。如果存在，必须是严格 SemVer，不能是浮动版本；如果导入的主流 Agent Skill 只有 `name` 和 `description`，安装器生成稳定版本：

```text
0.0.0+sha.<content_sha256前12位>
```

生成版本必须在预检页面明确标记为 `derived_version`，不能伪装成发布者提供的版本。相同内容重复导入保持同一生成版本，不同内容生成不同版本。

推荐字段：

- `version`；
- `author`；
- `license`；
- `compatibility.shieldchain`；
- `metadata.shieldchain.display_name`；
- `language`；
- `tags`；
- `roles`；
- `requested_tools`；
- `max_context_tokens`；
- `references`；
- `templates`。

兼容其他 Agent 常见的 `allowed-tools` 字段时，安装器只能将其映射为 `requested_tools` 提示，不能将其映射为服务端授权。无法识别的非安全字段保留在原始清单中但不参与运行；`permissions`、`sudo`、`network_access`、`secrets`、`shell`、`auto_approve` 等伪权限字段必须列为风险提示。字段存在不代表获得权限。

### 4.4 包体限制

建议默认配置：

- ZIP 总上传大小：10 MiB；
- 解压后总大小：25 MiB；
- 文件数量：最多 200；
- 单文件大小：最多 2 MiB；
- `SKILL.md`：最多 100,000 字符；
- Front Matter：最多 32 KiB；
- references 总注入量：每次运行最多 4,000 Token；
- 单次运行激活 Skill：最多 3 个；
- Skill 总上下文预算：默认 4,000 Token，硬上限 8,000 Token；
- ZIP 压缩比：最多 100:1；
- 路径深度：最多 8 层。

这些值必须进入 `Settings`，有上下界验证，生产环境不得通过客户端覆盖。

## 5. 安装来源与信任等级

### 5.1 支持来源

第一版支持：

1. **本地上传**：管理员上传单个 `.zip`；
2. **GitHub URL**：仅允许 `https://github.com/<owner>/<repo>`、GitHub archive 或 release asset；
3. **内置 Skill**：随 ShieldChain 发布并由代码仓库维护。

不支持任意 HTTP、IP 地址、URL 重定向到非 GitHub 域名、SSH Git URL、带用户信息 URL、私有网络地址和客户端提供认证头。

### 5.2 信任等级

- `bundled`：随 ShieldChain 版本发布；
- `verified`：来源和摘要经过管理员确认，可选绑定允许的发布者/仓库；
- `unverified`：本地上传或未建立发布者信任，只允许预览，管理员明确确认后才能启用；
- `quarantined`：扫描失败、内容异常或运行时完整性失败；
- `revoked`：管理员或安全策略撤销。

“verified”不代表内容绝对安全，只代表来源与锁定摘要符合已配置规则。

## 6. 两阶段安装流程

### 6.1 阶段 A：预检

1. 接收上传或 GitHub URL；
2. 校验请求大小、来源、HTTPS、重定向和下载上限；
3. 下载到服务端生成的临时文件，不使用来源文件名作为路径；
4. 计算原始包 SHA-256；
5. 安全解压到隔离临时目录；
6. 拒绝路径穿越、链接、设备文件、大小写碰撞、压缩炸弹和禁用扩展；
7. 解析 `SKILL.md` 和 YAML Front Matter；
8. 校验名称、版本、兼容范围、角色、引用路径和 Token 上限；
9. 扫描高风险指令，例如绕过审批、泄露提示词、执行 Shell、读取凭据、关闭安全控制；
10. 生成规范化内容摘要、文件清单、请求工具差异和风险报告；
11. 保存短时有效的 `preview_id` 和确认摘要；
12. 返回前端供管理员确认，不立即启用。

### 6.2 阶段 B：确认安装

管理员提交 `preview_id` 和预检摘要后：

1. 服务端重新校验预检未过期；
2. 校验预检内容摘要和临时包一致，防止 TOCTOU；
3. 将不可变包复制到 `skills_content_root/<skill_id>/<version>/<sha256>/`；
4. 原子写入 Skill、版本、安装状态和审计事件；
5. 默认状态为 `disabled`，管理员再显式启用；
6. 清理临时目录；
7. 返回安装版本、哈希、风险、兼容状态和可用角色。

安装任一步失败时不得留下“数据库已安装但文件缺失”或“文件已存在但数据库未提交”的半状态。

## 7. 持久化模型

建议新增以下表。

### 7.1 `skills`

保存稳定身份：

- `id` UUID；
- `name`；
- `display_name`；
- `created_at`；
- `updated_at`；
- `latest_version_id`；
- 唯一约束：规范化 `name`。

### 7.2 `skill_versions`

不可变版本：

- `id` UUID；
- `skill_id`；
- `version`；
- `description`；
- `author`；
- `license`；
- `compatibility_spec`；
- `package_sha256`；
- `content_sha256`；
- `storage_key`；
- `source_type`；
- `source_url` 的脱敏规范化值；
- `source_ref`；
- `trust_level`；
- `scan_status`；
- `scan_findings_json`；
- `manifest_json`；
- `created_at`；
- 唯一约束：`skill_id + version + content_sha256`。

相同名称和版本但内容不同必须拒绝，不能静默覆盖。

### 7.3 `skill_installations`

租户安装状态：

- `id` UUID；
- `tenant_id`；
- `skill_id`；
- `active_version_id`；
- `status`：`disabled/enabled/quarantined/revoked`；
- `enabled_by`；
- `enabled_at`；
- `revision`；
- 唯一约束：`tenant_id + skill_id`。

### 7.4 `skill_role_bindings`

管理员批准的角色绑定：

- `installation_id`；
- `agent_role`；
- `enabled`；
- `max_context_tokens_override`，只能降低包声明和系统硬上限；
- 唯一约束：`installation_id + agent_role`。

### 7.5 `skill_audit_events`

只追加审计：

- `id`；
- `tenant_id`；
- `skill_id`；
- `version_id`；
- `actor_id`；
- `action`；
- `reason_code`；
- `request_id`；
- `details_json` 的公开安全摘要；
- `created_at`。

### 7.6 `agent_run_skills`

运行绑定：

- `run_id`；
- `tenant_id`；
- `agent_role`；
- `skill_version_id`；
- `content_sha256`；
- `selection_reason_code`；
- `injected_tokens`；
- `created_at`。

该表确保历史轨迹可以说明“当时使用了哪个确切 Skill”。

## 8. 后端模块设计

建议新增：

```text
backend/src/shieldchain/skills/
├── __init__.py
├── domain.py          # Skill、版本、安装、状态和原因码
├── schemas.py         # API 输入输出 Schema
├── parser.py          # Front Matter 与 Markdown 解析
├── validation.py      # 字段、兼容范围、路径和内容限制
├── scanner.py         # 高风险内容和包体安全扫描
├── package.py         # ZIP 清单、安全解压和规范化摘要
├── storage.py         # 不可变本地包存储
├── persistence.py     # SQLAlchemy 行模型
├── repositories.py    # 原子安装、版本和审计仓储
├── installer.py       # 预检、确认、升级、回滚、卸载
├── catalog.py         # 启用状态和角色候选目录
├── selector.py        # 候选过滤与受控模型选择
├── loader.py          # 正文和引用文件按预算加载
└── service.py         # API 编排服务
```

新增 API：

```text
backend/src/shieldchain/api/skills.py
```

新增迁移：

```text
backend/migrations/versions/20260821_01_add_skill_runtime.py
```

修改：

```text
backend/src/shieldchain/core/config.py
backend/src/shieldchain/main.py
backend/src/shieldchain/db/base.py
backend/src/shieldchain/agents/context.py
backend/src/shieldchain/agents/security.py
backend/src/shieldchain/agents/orchestrator.py
backend/src/shieldchain/operations/react_collaboration.py
```

## 9. API 设计

所有接口使用服务端租户和主体身份，客户端不得提交或覆盖 `tenant_id`、`principal_id`、角色权限和信任等级。

**生产阻断条件**：当前项目部分 API 仍使用服务端 demo tenant/principal。Skills 安装、启用、升级、回滚和卸载属于管理员控制面；在真实管理员认证、RBAC 和租户绑定完成前，这些写接口必须由 `skills_management_enabled=false` 保持关闭，不能因为身份由服务端填充就宣称具备生产授权。测试环境可以使用固定 demo 身份，但必须有测试证明生产配置会拒绝启动或拒绝开放写接口。

### 9.1 目录与详情

```http
GET /api/v1/skills
GET /api/v1/skills/{skill_id}
GET /api/v1/skills/{skill_id}/versions
GET /api/v1/skills/{skill_id}/audit
```

支持按状态、角色、标签和名称过滤，但必须限制分页大小。

### 9.2 上传预检

```http
POST /api/v1/skills/previews/upload
Content-Type: multipart/form-data
```

字段只允许：

- `file`；
- `requested_trust`，只能请求，不能决定最终信任；
- `role_bindings`。

### 9.3 GitHub 预检

```http
POST /api/v1/skills/previews/github
Content-Type: application/json
```

请求示例：

```json
{
  "repository": "https://github.com/example/security-skills",
  "ref": "v1.2.0",
  "subdirectory": "skills/alert-triage",
  "expected_sha256": "可选但推荐的64位摘要"
}
```

服务端必须：

- 只允许配置中的 GitHub 主机；
- 解析并规范化 owner/repo/ref；
- ref 必须锁定到提交 SHA 或不可变发布资产后才能确认安装；
- 禁止 URL 用户信息、任意端口和跨域重定向；
- 执行 DNS 与最终连接目标检查，防止 SSRF；
- 不接受客户端提供的 Authorization Header。

### 9.4 确认安装

```http
POST /api/v1/skills/previews/{preview_id}/install
```

请求必须包含预检返回的确认摘要，防止确认错误版本。

### 9.5 生命周期

```http
POST   /api/v1/skills/{skill_id}/enable
POST   /api/v1/skills/{skill_id}/disable
POST   /api/v1/skills/{skill_id}/rollback
DELETE /api/v1/skills/{skill_id}
```

- `enable` 必须检查版本兼容和扫描状态；
- `disable` 不影响已经开始并锁定版本的运行，但阻止新运行选择；
- `rollback` 只能切换到已安装、未撤销、兼容的不可变版本；
- `DELETE` 默认只移除租户安装；内容仅在无任何引用和留存策略允许时清理。

## 10. Skill 发现与选择

### 10.1 确定性候选过滤

`SkillCatalog` 先按以下条件过滤：

1. 当前租户已安装；
2. 状态为 `enabled`；
3. 活跃版本扫描通过；
4. 与当前 ShieldChain 版本兼容；
5. 管理员已将该 Skill 绑定当前角色；
6. 当前任务未命中明确的“不适用条件”；
7. Skill 请求工具与当前角色工具至少不存在强制冲突；
8. Skill 及总预算未超限。

### 10.2 模型选择

只有确定性过滤后的候选描述可以交给模型。模型只返回：

```json
{
  "action": "activate_skills",
  "skills": [
    {"id": "UUID", "reason_code": "task_match", "public_reason": "用于规范告警分诊步骤"}
  ]
}
```

服务端必须再次验证：

- ID 来自候选集；
- 数量不超过3；
- 无重复；
- 原因码符合固定格式；
- 总 Token 不超限。

模型不可用或输出无效时，第一版默认不自动激活 Skill；只有管理员配置了 `always_on` 且角色绑定明确的内置 Skill 才可确定性加载。不得为了“看起来使用了 Skill”而虚构选择结果。

### 10.3 选择时机

- 在总控选择角色之后、专业角色第一次工具决策之前选择；
- 同一角色运行内锁定 Skill 集，不允许每轮变化；
- 运行恢复时读取 `agent_run_skills`，不得重新选择新版本；
- 新版本仅影响之后启动的运行。

## 11. 上下文注入与渐进加载

### 11.1 新增上下文分区

在 `ContextSectionName` 中增加：

```text
SKILLS = "skills"
```

该分区放在 `ALLOWED_ACTIONS` 之后、案件事实和不可信证据之前。每个注入块至少包含：

- Skill 名称；
- 版本；
- 内容 SHA-256；
- 适用角色；
- 权限声明无授权效力的边界；
- 经过预算裁剪的正文。

### 11.2 信任语义

Skill 属于“管理员批准的过程指导”，不是原始证据，也不是系统授权。应增加独立内容类型，例如：

```text
ContextContentType.SKILL_GUIDANCE
```

该类型：

- 只能由服务端根据已安装版本生成；
- 客户端和模型不能构造；
- 只投影规范化后的 Skill 文本和版本信息；
- 不允许出现 tenant、principal、凭据、原始提示词和内部策略字段；
- 在提示中明确 `cannot_grant_authority=true`；
- 仍执行敏感信息脱敏和风险标记。

### 11.3 渐进披露

第一版按三层加载：

1. 候选阶段只提供 `name/description/tags/roles`；
2. 激活后加载 `SKILL.md` 正文；
3. 引用文件只在正文明确声明且预算允许时加载。

引用文件读取必须使用服务端生成的资源 ID，不能接受模型提供任意路径。第一版可以先由加载器按清单加载必要引用，不必向模型暴露通用文件读取工具。

## 12. 与当前 Agent 和工具系统接线

### 12.1 `RealDataAgentTeam`

在 `_run_role` 前增加：

1. 获取当前角色 Skill 候选；
2. 调用受控 `SkillSelector`；
3. 锁定版本并记录 `agent_run_skills`；
4. 将 Skill 指导加入角色 Prompt；
5. 将 Skill 请求工具与角色允许工具做交集；
6. 在 `AgentRoleRunView` 增加公开 Skill 摘要。

### 12.2 两条智能体路径统一接线

当前仓库同时存在：

- `agents/orchestrator.py` 使用结构化上下文端口的编排路径；
- `operations/react_collaboration.py` 自行拼接角色 Prompt 的真实数据 ReAct 路径。

只修改 `agents/context.py` 会遗漏真实数据路径。应由两个入口共同调用：

```text
shieldchain.skills.selector.SkillSelectionService
shieldchain.skills.context.SkillContextProjector
```

共享服务返回已完成角色过滤、版本锁定、权限交集和 Token 预算的 Skill 块。两条路径必须使用同一 DTO、同一原因码和同一运行绑定逻辑，并分别有集成测试。短期只把 `operations/react_collaboration.py` 的字符串角色映射到固定 `AgentRole`；不得借 Skills 实施一次性重写整个多智能体架构。

### 12.3 固定角色端口

`ProfessionalRoleRegistry` 继续要求每个角色恰好一个适配器。Skill 不新增角色类，只增强现有角色的过程指导。第一版不允许 Skill 定义第八个 AgentRole，避免破坏持久化枚举和安全策略。

### 12.4 可信工具网关

`TrustedToolRegistry`、`DeterministicToolPolicy` 和审批服务保持唯一授权源：

- Skill 声明 `block_ip` 不会注册该工具；
- Skill 声明“自动批准”无效；
- 高风险动作仍只能由响应规划角色提出 `proposed:*`；
- 真实执行仍经过工具注册、参数绑定、策略、审批、租约、适配器和验证；
- 运行轨迹同时记录 Skill 来源与真实工具决策，便于审计。

### 12.5 RAG

Skill references 不自动进入 RAG，避免一份内容同时具有“过程指导”和“知识证据”两种语义。若管理员希望引用材料进入知识库，必须通过现有知识库上传和发布流程单独完成。

## 13. 前端 Skills 工作台

新增路由：

```text
/skills
```

建议新增：

```text
frontend/src/features/skills/
├── SkillsPage.tsx
├── SkillDetailPage.tsx
├── InstallSkillDialog.tsx
├── SkillRiskReview.tsx
├── api.ts
├── types.ts
├── skills.css
├── SkillsPage.test.tsx
├── InstallSkillDialog.test.tsx
└── api.test.ts
```

页面功能：

- 已安装 Skill 列表；
- 状态、版本、来源、信任等级、角色绑定和哈希；
- 上传 ZIP；
- 输入 GitHub URL、ref 和子目录；
- 安装前风险预览；
- 展示请求工具与实际可用工具差异；
- 启用、禁用、升级、回滚和卸载；
- 查看 `SKILL.md` 的安全渲染预览；
- 查看文件清单和审计事件；
- 明确提示“Skill 不授予工具权限，不执行包内代码”。

前端不得：

- 渲染未清洗 HTML；
- 自动跟随 Skill 内容中的链接；
- 展示临时路径、内部存储键和敏感扫描细节；
- 根据客户端判断设置 `verified`；
- 在未显示风险差异时一键启用未验证 Skill。

## 14. 配置项

建议在 `Settings` 增加：

```text
skills_enabled
skills_shadow_mode
skills_management_enabled
skills_content_root
authorized_skill_github_hosts
skills_max_upload_bytes
skills_max_expanded_bytes
skills_max_files
skills_max_file_bytes
skills_max_compression_ratio
skills_max_path_depth
skills_max_body_characters
skills_max_active_per_role
skills_default_context_tokens
skills_max_context_tokens
skills_preview_ttl_seconds
skills_remote_download_timeout_seconds
skills_remote_redirect_limit
```

所有数值都必须使用 Pydantic 上下界校验。生产环境必须拒绝空的存储根、通配 GitHub 主机和不安全 URL 方案；`skills_enabled` 默认关闭，`skills_management_enabled` 只有在真实管理员认证与 RBAC 已配置时才允许开启。

## 15. 错误与原因码

使用稳定原因码，不把内部异常直接返回前端：

```text
skill_package_invalid
skill_manifest_invalid
skill_path_unsafe
skill_archive_bomb_rejected
skill_file_type_rejected
skill_content_too_large
skill_name_version_conflict
skill_source_not_allowed
skill_source_unpinned
skill_download_failed
skill_digest_mismatch
skill_scan_rejected
skill_compatibility_failed
skill_preview_expired
skill_install_conflict
skill_not_found
skill_enable_denied
skill_version_quarantined
skill_context_budget_exceeded
skill_selection_invalid
skill_integrity_failed
```

日志记录 request ID、Skill ID、版本、摘要前缀和原因码，不记录完整 Skill 内容、远程凭据或内部路径。

## 16. 安全威胁与控制

| 威胁 | 必须控制 |
| --- | --- |
| ZIP Slip/路径穿越 | 规范化每个成员路径，拒绝绝对路径、`..`、链接和跨根目录写入 |
| 压缩炸弹 | 上传、解压大小、文件数、压缩比和超时硬限制 |
| SSRF | GitHub域名白名单、HTTPS、DNS/目标检查、重定向复核、禁止客户端认证头 |
| Skill提示注入 | 固定优先级、管理员预览、风险扫描、`cannot_grant_authority`、服务端二次校验 |
| 权限扩大 | 工具集合只做交集；Skill不进入授权决策 |
| 名称劫持 | 规范化名称唯一；同版本异内容拒绝；显示来源、版本和哈希 |
| 供应链替换 | ref锁定提交SHA/发布摘要；不可变存储；升级重新确认 |
| 符号链接逃逸 | 拒绝 symlink/hardlink/reparse point，读取时复核存储根身份 |
| 任意代码执行 | 第一版拒绝scripts和可执行文件；解析器不加载Python对象 |
| 凭据泄露 | 内容扫描与脱敏；Skill拿不到环境变量、数据库连接和工具凭据 |
| 跨租户访问 | 所有安装、列表、绑定和审计查询使用服务端 tenant |
| 运行漂移 | 每次运行锁定version+hash，恢复时复用，不跟随latest |
| 删除破坏审计 | 有运行引用的版本只做逻辑卸载，按留存策略延迟物理清理 |

## 17. 测试策略

### 17.1 单元测试

建议新增：

```text
backend/tests/unit/skills/test_domain.py
backend/tests/unit/skills/test_parser.py
backend/tests/unit/skills/test_validation.py
backend/tests/unit/skills/test_package.py
backend/tests/unit/skills/test_scanner.py
backend/tests/unit/skills/test_storage.py
backend/tests/unit/skills/test_installer.py
backend/tests/unit/skills/test_catalog.py
backend/tests/unit/skills/test_selector.py
backend/tests/unit/skills/test_loader.py
```

必须覆盖：

- 合法 Front Matter 和正文；
- 缺少 `name/description`、重复键、非 UTF-8、过长描述、显式非法 SemVer；
- 缺少 `version` 时生成稳定的 `derived_version`；
- YAML alias/anchor 资源耗尽、递归对象和非标类型标签；
- 角色和工具名规范化；
- 同名同版本同内容幂等；
- 同名同版本异内容拒绝；
- 路径穿越、绝对路径、链接、大小写碰撞；
- 文件数、大小、深度、压缩比边界；
- 高风险权限和绕过审批文本扫描；
- Skill 请求工具不能扩大角色工具集合；
- 候选筛选、模型无效选择和 Token 截断；
- 版本锁定、禁用、回滚和完整性失败隔离。

### 17.2 集成测试

新增：

```text
backend/tests/integration/api/test_skills_api.py
backend/tests/integration/skills/test_skill_runtime.py
backend/tests/integration/skills/test_skill_migration.py
backend/tests/integration/skills/test_skill_security.py
```

场景：

1. 上传预检 → 确认安装 → 默认禁用；
2. 启用 → 角色候选可见 → Agent锁定版本；
3. 重启服务 → 安装与启用状态保持；
4. 安装新版本 → 旧运行继续使用旧哈希，新运行使用新版本；
5. 禁用 → 新运行不再选择；
6. 回滚 → 新运行使用回滚版本；
7. 卸载 → 历史运行仍可审计；
8. Skill 请求 `block_ip` → 不增加当前报告 Agent 权限；
9. 恶意 ZIP 和 GitHub 重定向被拒绝；
10. 存储文件被篡改 → Skill隔离并转安全降级。

### 17.3 前端测试

必须覆盖：

- 列表加载、空状态、错误状态；
- 上传和GitHub两种安装入口；
- 风险预览和确认摘要；
- 未验证Skill不能绕过确认直接启用；
- 启停、升级、回滚和卸载二次确认；
- 不渲染Skill原始HTML和脚本；
- 来源、版本、哈希和工具权限差异可见；
- 键盘导航和状态提示。

### 17.4 安全回归

必须验证：

- Prompt中系统规则始终位于Skill之前；
- Skill内容不能改变 tenant、principal、角色、工具风险和审批结果；
- Skill不能触发Shell、网络请求或动态导入；
- 安装URL不能访问回环、私网、链路本地和云元数据地址；
- 错误不会返回本地路径、堆栈、凭据或完整扫描规则；
- 跨租户读取、启用和卸载全部拒绝；
- 删除或升级不会破坏运行审计。

## 18. 分阶段实施计划

### 阶段0：特征保护和当前行为刻画

**目标**：保证功能关闭时现有系统行为不变，为后续增量接线建立基线。

先写测试证明：七角色集合不变；`ProfessionalRoleRegistry` 仍要求角色完整；工具白名单不受 Skill 文本影响；`skills_enabled=false` 时两条智能体路径的 Prompt、工具调用和公开输出保持现状；`skills_management_enabled=false` 时所有管理写接口不可用。

建议测试：

```text
backend/tests/unit/skills/test_feature_disabled.py
backend/tests/unit/skills/test_fixed_roles.py
backend/tests/unit/skills/test_tool_authority_regression.py
```

提交：`test: protect behavior before skills runtime`。

完成标准：特征关闭基线可重复，任何工具权限差异都会使测试失败。

### 阶段1：领域合同和解析器

**目标**：冻结包格式、领域对象、状态和原因码。

文件：

```text
backend/src/shieldchain/skills/domain.py
backend/src/shieldchain/skills/parser.py
backend/src/shieldchain/skills/validation.py
backend/tests/unit/skills/test_domain.py
backend/tests/unit/skills/test_parser.py
backend/tests/unit/skills/test_validation.py
```

步骤：

1. 先写 Front Matter、SemVer、角色和工具声明失败测试；
2. 运行聚焦测试，确认 RED；
3. 实现最小不可变领域对象和解析器；
4. 运行聚焦测试，确认 GREEN；
5. 运行 Ruff；
6. 提交 `feat: define skill package contracts`。

完成标准：合法包能生成规范化元数据；非法字段使用稳定原因码拒绝；不存在文件或网络副作用。

### 阶段2：安全包处理与不可变存储

**目标**：安全处理 ZIP 和本地包存储。

文件：

```text
backend/src/shieldchain/skills/package.py
backend/src/shieldchain/skills/scanner.py
backend/src/shieldchain/skills/storage.py
backend/tests/unit/skills/test_package.py
backend/tests/unit/skills/test_scanner.py
backend/tests/unit/skills/test_storage.py
```

步骤：按 TDD 分别实现路径、链接、大小、压缩比、内容扫描、原子写入、哈希和篡改检测。

提交：`feat: add contained skill package storage`。

完成标准：恶意包全部在写入持久存储前失败；合法包按不可变哈希存储；失败清理临时文件。

### 阶段3：数据库、迁移与安装服务

**目标**：实现版本、租户安装、角色绑定和审计。

文件：

```text
backend/src/shieldchain/skills/persistence.py
backend/src/shieldchain/skills/repositories.py
backend/src/shieldchain/skills/installer.py
backend/migrations/versions/20260821_01_add_skill_runtime.py
backend/tests/unit/skills/test_installer.py
backend/tests/integration/skills/test_skill_migration.py
```

步骤：先写迁移升级/降级和原子安装失败测试，再实现表、仓储、预检确认、启停、升级、回滚和逻辑卸载。

提交：`feat: persist skill installations and versions`。

完成标准：迁移往返通过；重启后状态保持；同版本异内容拒绝；安装无半状态。

### 阶段4：API与远程来源

**目标**：提供受控上传和GitHub安装API。

文件：

```text
backend/src/shieldchain/skills/schemas.py
backend/src/shieldchain/skills/service.py
backend/src/shieldchain/api/skills.py
backend/src/shieldchain/core/config.py
backend/src/shieldchain/main.py
backend/tests/integration/api/test_skills_api.py
backend/tests/integration/skills/test_skill_security.py
```

步骤：先实现本地上传预检/确认，再实现GitHub固定ref下载；每个入口都补请求大小、SSRF、重定向和公开错误测试。

提交：`feat: expose controlled skill installation api`。

完成标准：管理员可完成预检、确认、启停、版本查询、回滚和卸载；外部来源不能越过GitHub白名单。

### 阶段5：运行时目录、选择和上下文

**目标**：让现有角色安全选择并加载Skill。

文件：

```text
backend/src/shieldchain/skills/catalog.py
backend/src/shieldchain/skills/selector.py
backend/src/shieldchain/skills/loader.py
backend/src/shieldchain/agents/context.py
backend/src/shieldchain/agents/security.py
backend/src/shieldchain/operations/react_collaboration.py
backend/tests/unit/skills/test_catalog.py
backend/tests/unit/skills/test_selector.py
backend/tests/unit/skills/test_loader.py
backend/tests/integration/skills/test_skill_runtime.py
```

步骤：先写“不得扩大工具权限”、候选过滤、模型无效选择、Token预算、版本锁定和恢复测试，再接入 `RealDataAgentTeam`。

提交：`feat: activate bounded skills in agent roles`。

完成标准：Agent只加载已启用兼容Skill；公开轨迹包含版本和哈希；模型或Skill失败时安全降级；工具权限不扩大。

### 阶段6：前端Skills工作台

**目标**：提供完整安装和生命周期管理体验。

文件：

```text
frontend/src/features/skills/*
frontend/src/app/router.tsx
frontend/src/app/App.tsx
```

步骤：按 API 客户端、列表、安装预览、风险确认、详情、版本/回滚、审计顺序逐个测试和实现。

提交：`feat: add skills management workspace`。

完成标准：用户可以不使用命令行完成安装、检查、启停、升级、回滚和卸载；安全边界清晰可见。

### 阶段7：文档、样例与全量验收

新增两个只读示例Skill：

```text
sample_skills/alert-triage/SKILL.md
sample_skills/vulnerability-response/SKILL.md
```

它们不得包含脚本，不得请求高风险处置工具。同步更新：

```text
README.md
docs/README.md
docs/architecture/system-design.md
docs/architecture/context-engineering.md
docs/architecture/trusted-tool-calling.md
docs/standards/security-standards.md
docs/standards/testing-standards.md
docs/operations/skills-management.md
development-logs/YYYY-MM-DD.md
```

提交：`docs: document installable skills runtime`。

完成标准：聚焦测试、后端全量测试、前端测试、类型检查、Lint、迁移往返、Docker配置检查和人工安全检查全部通过。

### 发布启用与回滚顺序

1. **基础设施**：`skills_enabled=false`，只部署表、解析器、包安全和管理 API；
2. **影子选择**：`skills_shadow_mode=true`，记录“将选择哪些 Skill”，但不注入模型；
3. **测试租户**：只对测试租户注入，比较事实漂移、引用完整率、Token、失败率和工具调用差异；
4. **受控生产**：仅启用内置或已验证来源，第三方安装只开放给真实管理员；
5. **逐步迁移**：行为等价测试充分后，才将部分硬编码过程提示迁为内置 Skill；系统安全规则、工具目录、白名单、输出 Schema、状态机和审批始终留在代码中。

紧急回滚只需设置 `skills_enabled=false` 并停止新运行绑定；已锁定运行按策略完成或转人工。不得在回滚时删除数据库表、不可变包或历史运行绑定。物理清理由独立延迟 GC 处理。

## 19. 精确验证命令

Windows项目环境建议：

```powershell
conda run -n ShieldChain python -m pytest backend/tests/unit/skills -q
conda run -n ShieldChain python -m pytest backend/tests/integration/skills -q
conda run -n ShieldChain python -m pytest backend/tests/integration/api/test_skills_api.py -q
conda run -n ShieldChain python -m pytest backend/tests -q
conda run -n ShieldChain python -m ruff check backend/src backend/tests
conda run -n ShieldChain python -m ruff format --check backend/src backend/tests
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
npm run lint --prefix frontend
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml -f compose.server.yaml config --quiet
```

迁移必须在临时数据库验证：

```powershell
$env:DATABASE_URL = "sqlite:///./data/skills-migration-test.db"
conda run -n ShieldChain python -m alembic -c backend/alembic.ini upgrade head
conda run -n ShieldChain python -m alembic -c backend/alembic.ini downgrade -1
conda run -n ShieldChain python -m alembic -c backend/alembic.ini upgrade head
```

验收报告必须记录真实命令和返回结果，不能只写“测试通过”。

## 20. 验收标准

只有以下条件全部满足，Skills 功能才可标记完成：

1. 合法Skill可通过上传和固定GitHub来源预检、安装、启用；
2. 安装前能看到来源、版本、哈希、文件清单、风险和工具权限差异；
3. Skill版本和启用状态在重启后保持；
4. Agent按任务和角色选择不超过3个Skill；
5. 每次运行锁定Skill版本与哈希并进入公开轨迹；
6. Skill不能新增角色、注册工具、扩大工具白名单或改变审批；
7. 包内任何脚本和可执行文件均不运行；
8. 路径穿越、链接、压缩炸弹、SSRF、同版本异内容和篡改全部有自动化测试；
9. Skill上下文受固定优先级、字段投影和Token预算控制；
10. 禁用影响新运行但不破坏正在执行和历史审计；
11. 升级和回滚不会静默改变已开始运行；
12. 前端可以完成完整生命周期管理并安全渲染内容；
13. 后端全量测试、前端测试、类型检查、Lint和迁移往返通过；
14. README、架构、安全、测试、操作文档和开发日志与代码一致；
15. 两条智能体运行路径都通过同一选择和上下文投影服务，且功能关闭时行为保持不变；
16. 未配置真实管理员认证和 RBAC 时，生产环境不能开放 Skills 管理写接口。

## 21. 后续演进

完成第一版并稳定运行后，可以单独评审：

- 发布者签名和组织信任策略；
- 私有GitHub仓库的服务端凭据代理；
- Skill市场索引和可验证来源清单；
- Skill组合冲突检测和优先级；
- 基于人工反馈的Skill效果评测；
- 只读 `skills.resources.read` 渐进披露工具；
- 在容器/微虚拟机沙箱内执行签名脚本的高风险扩展；
- 将MCP工具依赖声明与Skill安装检查联动；
- 与其他Agent的 `SKILL.md` 格式兼容性测试。

这些能力不得提前混入第一版，尤其不能因为追求“像通用Agent一样方便”而让Skill获得任意代码执行或工具授权。

## 22. 设计决策摘要

| 决策 | 选择 | 原因 |
| --- | --- | --- |
| 包格式 | `SKILL.md` + YAML Front Matter | 兼容主流Agent习惯，易于人工审查和Git版本控制 |
| 第一版脚本 | 全部禁止执行 | ShieldChain处理高风险安全数据，供应链与RCE风险不可接受 |
| 安装流程 | 预检 + 人工确认 | 兼顾快速安装、来源可见和风险审计 |
| 版本存储 | 不可变版本 + SHA-256 | 防止同版本静默替换和运行漂移 |
| Skill选择 | 确定性候选过滤 + 受控模型选择 | 保留自主性，同时不让模型越过租户、角色和预算边界 |
| 工具权限 | 服务端交集 | Skill只能收窄，不能扩大权限 |
| Skill信任 | 管理员批准的过程指导 | 高于普通外部数据，但低于系统规则、安全边界和授权策略 |
| 运行升级 | 新运行生效，旧运行锁定 | 保证恢复、一致性和审计可复现 |
| RAG关系 | 分离存储和语义 | 避免过程指令被当作事实证据，或知识文档被当作可执行流程 |
| 首批入口 | ZIP上传 + 锁定GitHub来源 | 覆盖快速安装场景，同时避免任意URL下载 |
