# MCP、响应规划与安全闭环加固合并交接说明

> 文档状态：待项目主导人合并（核对日期：2026-08-28）。本文只说明如何评审和合并既有分支，
> 不授权真实设备处置，也不把合并前测试结果等同于合并后验收结果。

## 1. 交接结论

- 合并来源为 `origin/codex/mcp-safety-hardening`；评审时必须先 `git fetch --prune origin`，再以远端最新提交为准。
- 该分支完整包含 `codex/mcp-agent-safety-loop` 的实现，后者停在 `9852903`，不需要也不应再次单独合并。
- `da61cd1` 是 Task 15 实现、测试证据和既有文档同步完成时的提交；本交接材料会作为后续纯文档提交位于其上。
- 2026-08-28 核对时，远端默认集成分支为 `origin/codex/phase-6-react-loop`，提交为 `7f43c27`。该提交可能继续变化，不能把本文记录当成永久固定的目标提交。
- 当前预合并只有 `backend/src/shieldchain/operations/mcp_tools.py` 存在内容冲突。最终合并和冲突取舍应由项目主导人审查，不应自动选择整文件的 `ours` 或 `theirs`。

## 2. 分支范围

本次来源分支从共同基线 `b2254547` 起包含两组工作。

### 2.1 Task 0～14 与同历史文档序列

| 提交 | 内容 | 合并关注点 |
| --- | --- | --- |
| `74fbe7e`、`732f4d8` | Skills 运行时实施与授权设计文档 | 这是同一历史中的独立文档工作；主导人应明确接受，不要在不知情时顺带合入 |
| `01f5443` | MCP、Agent Tool、响应规划与安全闭环统一计划 | 后续实现和验收的设计基线 |
| `33e0b96` | 忽略本地 `AGENTS.md` | 只提交 `.gitignore` 规则，不提交本地指令文件 |
| `d71e378` | MCP 官方 SDK 协议兼容基线 | 锁定 MCP `2026-07-28` 兼容行为 |
| `6869c57`、`c0ec691` | 协议无关 Agent Tool 合同与明确失败语义 | 保留旧 MCP façade 兼容别名，不把失败解释为空结果 |
| `8064917` | 四类只读工具的标准 MCP Server | 网络入口默认关闭，生产启用依赖真实鉴权与 TLS |
| `8164069` | 通用 Agent Run 持久化 | 为运营运行、工具调用和计划提供统一关联 |
| `8f8fb18` | 有界 Agent Tool 调用审计 | 不保存 Token、原始私有载荷或异常堆栈 |
| `87cff4a` | MCP 传输与授权加固 | Host、Origin、JWT/JWKS、scope 和请求边界 |
| `9a635f8` | 外部 MCP 固定发现与快照 | 固定配置、SSRF/TLS/DNS/redirect 防护和 Schema revision |
| `c452ed8` | 受控外部 MCP 只读调用 | 预算、并发、速率、熔断、裁剪和独立凭据 |
| `a59a8a4`、`a136d31` | 严格、版本化响应计划和运营接线 | 模型只给候选；服务端重绑定身份、证据、目标、风险和审批 |
| `7223b63` | 计划动作映射到可信工具调用 | 一动作一调用，计划接受不等于工具审批 |
| `e01d10a` | 执行、验证、观察与重新规划闭环 | 只有必需验证成功才能报告成功 |
| `d051972` | MCP、计划和安全闭环公开投影 | 前端只展示裁剪后的公共状态，不展示私有推理或原始载荷 |
| `9852903` | Task 14 统一交付门禁 | MCP conformance、迁移、前后端和静态容器合同 |

如果目标分支不准备接收这两个 Skills 文档提交，主导人应在独立集成分支中显式评审和排除；
不能只挑选下面七个 Task 15 提交，因为它们依赖本表中的领域模型、迁移和工具网关实现。

### 2.2 Task 15 审查加固序列

| 提交 | 解决的问题 | 关键语义 |
| --- | --- | --- |
| `c86a5aa` | Adapter 调用期间的事务崩溃窗口 | 调用前耐久提交 `executing + lease`，成功后先提交 attempt 与 `verifying` |
| `22270b2` | 无 loop、等待执行和运行中计划无法持续恢复 | 应用生命周期周期扫描；单个有效租约或损坏计划不阻塞其他计划 |
| `0668e42` | Adapter 无实际 deadline、审批永久等待 | 执行超时为 `UNKNOWN`，验证超时为 `INCONCLUSIVE`，审批过期转人工 |
| `52e4c83` | 进程重启后仿真状态可能凭内存猜测 | 只根据持久化成功执行尝试重建状态 |
| `0b87a75` | 前端信任未知 JSON、smoke 模式失真 | 运行时逐字段公开投影校验；`-StaticOnly` 才跳过 Docker runtime |
| `3906d13` | 既有迁移格式阻塞全量 Ruff | 只做机械格式修复，没有行为重构 |
| `da61cd1` | 文档与最终验证证据不同步 | 同步架构、部署、测试、路线图和真实边界 |

详细语义见[统一实施方案](../plans/mcp-agent-tools-response-safety-loop-implementation.md)、
[可信工具调用](../architecture/trusted-tool-calling.md)、[部署手册](deployment-guide.md)和
[测试报告](test-report.md)。

## 3. 已实现与未验收边界

已实现并在来源分支验证：

- MCP `2026-07-28` 官方 SDK conformance；
- 四类内置只读 Agent Tool 的内部调用与标准 MCP 发布；
- 固定配置、受控发现和受限调用的外部只读 MCP Provider；
- 严格候选、服务端编译、版本化响应计划和可信调用映射；
- 离线仿真中的执行租约、执行/验证 deadline、恢复、ReAct 观察、失败 revision 和人工接管；
- 前端安全公开投影和运营报告运行时响应校验；
- migration head `20260824_08` 及临时 SQLite 升级、降一级、再升级保护。

以下仍未验收，合并说明、PR 和发布说明不得写成已完成：

- 真实身份平台、管理员 RBAC、上游 TLS 和真实外部 MCP peer；
- 真实防火墙、EDR、账号系统 Adapter 及真实设备回执；
- 真实新遥测回流和生产闭环；
- 本轮 Task 14 的 Docker runtime smoke；
- Wazuh review case 到案件级可执行计划的服务端目标确认和证据映射。

## 4. 当前冲突及解决原则

2026-08-28 在刷新远端引用后执行预合并，只有以下内容冲突：

```text
backend/src/shieldchain/operations/mcp_tools.py
```

冲突两侧都包含有效功能：

- 默认集成分支新增 `_behavior_categories`，从规范化告警证据中提取 NTA 行为类别，并追加到告警工具的公开条目；
- 来源分支把旧 `ReadOnlyMcpTool` 升级为协议无关 `ReadOnlyAgentTool`，增加稳定 identity、Provider/目录/Schema revision、异步结果合同，并保留旧名称和工厂兼容别名。

解决时必须同时保留：

1. `_behavior_categories` 的严格类型检查、非法 JSON 降级为空和最多五类去重限制；
2. `AlertMcpTool.call()` 中的行为类别公开摘要；
3. `ReadOnlyAgentTool`、`AgentToolExecutionResult` 和四类工具的稳定 identity/Provider 元数据；
4. `ReadOnlyMcpTool = ReadOnlyAgentTool` 与 `standard_mcp_tools = standard_agent_tools` 兼容入口；
5. 现有租户和时间窗口过滤、50 条公开结果上限及失败/空结果语义。

不要对该文件执行整文件 `git checkout --ours` 或 `git checkout --theirs`。`README.md` 和
`backend/tests/integration/api/test_operations_report.py` 在本次预合并中能够自动合并，但仍需检查最终内容。
如果远端继续前进，应重新运行预合并检查，不能假定冲突仍只有这一处。

## 5. 推荐合并流程

为避免直接改写默认分支，建议项目主导人在干净工作区创建临时集成分支：

```bash
git fetch --prune origin
git status --short --branch
git switch -c codex/mcp-safety-integration origin/codex/phase-6-react-loop
git merge --no-ff origin/codex/mcp-safety-hardening
```

出现冲突后按上一节合并 `mcp_tools.py`，然后确认没有未解决文件：

```bash
git diff --name-only --diff-filter=U
git diff --check
git status --short
```

若无法确认语义，保持冲突现场并联系两侧实现者；若决定放弃本次本地预合并，使用：

```bash
git merge --abort
```

冲突解决和测试通过后，再提交临时集成分支并通过 Pull Request 合入默认分支。不要 force push、
不要直接重写共享历史，也不要为了通过迁移而删除审批、调用、尝试、验证或计划审计。

## 6. 合并后验证

来源分支的记录为：后端 `1190 passed, 27 skipped`，前端 30 个文件、`107 passed`；Ruff、
TypeScript、ESLint、生产构建、`npm audit`、MCP conformance、迁移往返和四个 PowerShell AST
解析通过。该记录证明来源分支，不证明合并结果。

先运行冲突相关回归：

```bash
backend/.venv/Scripts/python.exe -m pytest --import-mode=importlib \
  backend/tests/unit/operations \
  backend/tests/integration/api/test_operations_report.py \
  backend/tests/integration/mcp \
  backend/tests/integration/response_planning/test_tool_gateway.py \
  backend/tests/unit/tools/test_gateway.py -q
```

随后必须执行[统一实施方案的完整验证命令](../plans/mcp-agent-tools-response-safety-loop-implementation.md#22-验证命令)，
至少包括：

- 后端全量 pytest 与 Ruff；
- 前端全量测试、TypeScript、ESLint、生产构建和依赖审计；
- 临时数据库 `upgrade head → downgrade -1 → upgrade head`；
- MCP conformance；
- Compose 静态合同；有 Docker daemon 时再执行 runtime smoke。

任何失败都应保留实际输出并定位根因，不能沿用来源分支的旧数字声明合并通过。

## 7. 主导人评审清单

- [ ] 已刷新远端并记录实际目标、来源和共同基线提交；
- [ ] 已确认来源分支包含旧 `mcp-agent-safety-loop`，没有重复合并；
- [ ] 已明确接受或排除两项 Skills 运行时文档提交；
- [ ] `mcp_tools.py` 同时保留 NTA 行为类别和协议无关 Agent Tool 合同；
- [ ] `UNKNOWN`/`INCONCLUSIVE` 状态不会自动重放变更动作；
- [ ] `approval_expired` 仍转 `needs_review`，迁移降级保护未被删除；
- [ ] 生产环境写控制仍在真实管理员 RBAC 完成前关闭；
- [ ] 合并后聚焦回归、完整门禁和迁移往返已重新执行；
- [ ] PR 明确区分内部/离线已实现能力与真实外部环境未验收能力；
- [ ] 合并失败时使用 abort 或后续 revert，不对共享分支执行 reset/force push。

## 8. 合并记录模板

主导人完成评审后可在 PR 或后续开发日志记录：

```text
target_branch=
target_commit=
source_branch=origin/codex/mcp-safety-hardening
source_commit=
merge_or_pr_commit=
conflicts_resolved=
focused_tests=
full_backend_tests=
full_frontend_tests=
migration_roundtrip=
mcp_conformance=
docker_runtime=
unaccepted_external_boundaries=
reviewer=
reviewed_at=
```
