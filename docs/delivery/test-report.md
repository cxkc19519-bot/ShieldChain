# ShieldChain 测试报告

<!-- ShieldChain acceptance boundary flags: these are intentionally explicit until the corresponding external environments are available. -->
DOCKER_RUNTIME_TESTED=False
NETWORK_ACCESS_TESTED=False
REAL_MODEL_PLANNING_TESTED=False
REAL_DEVICE_PATHS_TESTED=False
CI_RUNTIME_TESTED=False

> 文档状态：当前验证摘要（更新于 2026-08-28）。以下先记录分支整合验证，再保留各分支的历史结果；历史实时链路状态不代表本次重新验收。

## 2026-08-28 同门分支整合验证

集成分支：`codex/merge-team-20260828`；目标：仓库默认分支 `codex/phase-6-react-loop`。合并请求：[PR #1](https://github.com/cxkc19519-bot/ShieldChain/pull/1)。`main` 无共同祖先，本次未修改。

- 后端全量：`1194 passed, 26 skipped`（131.73 秒）；24 项为已退役仿真路由归档，1 项为可选本地模型运行环境，1 项为需显式开启的付费模型测试。
- 前端全量：30 个文件、114 项通过；TypeScript、ESLint 与 Vite 生产构建通过。
- 根目录脚本与 NTA 回归：60 项通过、4 个 subtests 通过；V11～V13 脚本和既有专项测试未被覆盖或删改。
- Ruff、`pip check` 通过；`npm audit --audit-level=moderate` 为 0 漏洞。
- Task 14 MCP conformance、16 项后端 smoke、13 项前端 smoke、12 项容器静态合同通过。
- 临时 SQLite 实际执行 `upgrade head → downgrade -1 → upgrade head`，最终为 `20260824_08`，没有操作真实数据库。
- 新增兼容性回归覆盖响应计划与公开审计字段共存、旧报告缺失新字段、拒绝非法/私有字段、RAG 成功/空/失败、工具失败不能解释成无风险、计划生成不能解释成已审批。
- 修复两项测试隔离问题：远程 MCP 快照测试使用固定时钟，Windows 解析器子进程测试显式添加测试模块路径；没有放松运行时过期检查或解析超时限制。
- 本次本地未验收 Docker 运行、真实外部 MCP/身份提供方、付费模型或真实设备执行；GitHub CI 结果以 PR #1 检查页为准。服务器未部署或重启。

## 历史验证记录

## 已执行验证

- Task 0～10 历史组合快照：MCP、智能体工具、通用运行、远程只读 Provider 与运营严格响应计划共 292 个测试通过；
- Task 0～11 后端组合回归（含可信工具完整单元/集成套件）：410 个测试通过；
- Task 0～12 后端组合回归（含 ReAct、闭环恢复和失败矩阵）：503 个测试通过；
- Task 13 后端相关组合（Agent、MCP、远程 MCP、响应计划、可信工具、ReAct、运营报告公开 API）：409 个测试通过；
- Task 13 聚焦 API 与计划/执行闭环：28 个测试通过，覆盖租户绑定、脱敏、revision 冲突、生产写控制关闭、空轨迹和计划—调用—验证映射；
- 响应计划专项：19 个测试通过，覆盖严格 JSON、越权字段、证据新鲜度、跨租户/跨事件隔离、依赖、revision、迁移和安全回滚；
- 计划到可信网关专项覆盖接受/拒绝、跨租户、重复决策、一动作一调用、策略与审批隔离、参数摘要变化、证据目标变化回滚、依赖验证和唯一租约；
- 安全闭环专项覆盖成功、审批等待、执行失败、未知结果不重放、验证失败/不可判断、状态查询、失败 revision、急停、预算、恢复执行和恢复验证；
- 运营响应规划接线覆盖合法零动作候选、无效 JSON、未知工具、跨运行证据、模型不可用、公开计划关联及零可信工具调用；
- Wazuh、运营报告、ReAct/RAG 新增关键后端测试：9 个通过；
- 前端全量：30 个测试文件、107 个测试通过；覆盖加载、错误、空、部分数据、取消、legacy 报告、超时状态、运行时契约和私有字段不渲染；
- TypeScript 类型检查、ESLint 和生产构建通过；
- Task 14 官方 SDK MCP conformance 通过：协议 `2026-07-28`、固定四工具只读目录、结构化调用和入站审计均符合合同；
- Alembic 临时 SQLite `upgrade head → downgrade -1 → upgrade head` 实际通过，最终 head 为 `20260824_08`；
- 后端 Ruff 全量通过；后端历史全量 `1190 passed, 27 skipped`；
- 前端安全补丁升级后 `npm audit --audit-level=moderate` 报告 0 漏洞；

### 智能体审计分支历史验证（2026-08-27）

- 智能体、运营报告、ReAct/RAG 关键后端回归：8 个通过；
- 交付文档与最终交付合同：6 个通过；
- 前端全量：26 个测试文件、95 个测试通过；
- TypeScript 类型检查、ESLint 与 Vite 生产构建通过；

- `compose.yaml + compose.server.yaml` 配置检查通过；
- `compose.yaml + compose.local-llm.yaml` 配置检查通过；
- 交付清单支持区分 `available` 与 `planned`，并检查未完成的 PPT、视频、ZIP 和校验和不会提前出现在仓库；
- 当前不宣称最终交付 smoke 已通过，最终版本冻结后需要重新执行完整门禁。

## 当前全量套件说明

2026-08-24 安全加固后端全量得到 `1190 passed, 27 skipped`，没有失败或错误。新增回归覆盖 Adapter 前的跨连接租约可见性、接受/审批提交断点、周期恢复、审批过期、执行/验证 deadline、全新进程内 Adapter 状态重建和迁移降级保护。跳过项均为显式边界：

- 已删除产品路由对应的固定钓鱼仿真 API 合同保留为归档 skip；不会为了表面全绿恢复旧功能；
- 本地模型服务轮廓需要可选 `local-rag`/`torch`，常规锁定测试环境未安装时显式跳过；
- 当前 Windows Python 测试进程找不到 `git` 时，fresh-checkout 跟踪文件检查跳过；迁移与 readiness 仍由其他当前合同覆盖。

前端最终全量为 `30` 个文件、`107 passed`，类型、Lint、构建均通过。运营报告响应现在逐字段执行运行时校验，不再以 TypeScript 断言接收未知 JSON；依赖审计为 0 漏洞。

PowerShell 四个门禁脚本通过 AST 语法解析。当前 Windows PowerShell 环境缺少 `npm.cmd`，因此没有把一次单命令 `verify.ps1` 运行标记为通过；同样的 Python、前端、迁移和安全门禁已分别实际执行。当前主机没有 Docker CLI，容器只完成静态 Compose/Nginx/供应链合同。

## 实时链路状态

- Wazuh/OpenSearch 与 ShieldChain Docker 服务已在学校服务器环境实际运行；
- vLLM 镜像和 Compose 配置已验证；
- Qwen3-30B-A3B 权重下载和推理服务启动尚受共享 GPU 可用性约束；
- 2026-07-28 的 DeepSeek 与真实 RAG 验收见历史快照报告；
- 真实处置设备链路仍未进行授权执行验收。

## 最终门禁边界标记

以下键由 Task 14 离线门禁和部署记录使用。`False` 表示本次没有获得对应外部环境的真实验收证据，不代表自动化测试失败：

```text
MCP_CONFORMANCE_TESTED=True
MIGRATION_ROUNDTRIP_TESTED=True
POWERSHELL_PARSE_TESTED=True
STATIC_CONTAINER_CONTRACT_TESTED=True
DOCKER_RUNTIME_TESTED=False
WINDOWS_COMBINED_VERIFY_TESTED=False
NETWORK_ACCESS_TESTED=False
REAL_MODEL_PLANNING_TESTED=False
REAL_IDENTITY_PLATFORM_TESTED=False
REAL_EXTERNAL_MCP_PEER_TESTED=False
REAL_DEVICE_PATHS_TESTED=False
```

离线官方 SDK conformance、静态容器合同、迁移往返和前后端测试可以在这些外部边界保持 `False` 时通过。只有保存真实授权环境、时间、操作者和结果证据后才能将对应值改为 `True`。

## 安全结论

- 测试不应输出或提交真实密钥、告警和客户数据；
- 只读 MCP 与可信处置网关必须分别测试；
- 模型失败、工具失败和 RAG 降级必须形成明确公开状态；
- 任何实时模型或安全设备测试都需要显式开关、预算、隔离数据和人工批准。
