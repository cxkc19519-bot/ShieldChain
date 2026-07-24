# ShieldChain 项目总结

## 项目定位

盾链智御（ShieldChain）是面向网络安全运营的智能体研究与比赛交付项目。它解决的核心问题不是让模型直接控制设备，而是把告警调查、知识依据、多智能体协作、工具执行、失败恢复和报告审计组成一个可授权、可验证、可追溯的闭环。

## 已交付能力

产品提供六个 React 工作区：运营总览、事件调查、智能体、知识库、处置中心、报告与审计。FastAPI 后端提供固定钓鱼仿真、产品级离线 RAG、多智能体上下文工程、受信工具网关、受预算约束的 ReAct 和人工接管 API。

工程交付包含 SQLite/Alembic 持久化、HTTP 安全、迁移感知 readiness、结构化日志脱敏、有界关闭、查询索引、非 root Dockerfile、Compose、可选容器 smoke、双平台 CI、精确依赖锁和完整文档。

## 核心创新

1. 上下文工程把事实、假设、模型结论、引用和工具结果分型，使用 tenant-bound 状态、revision/CAS 和 token 预算完成可审计交接。
2. 受信工具网关统一注册、策略、审批、幂等、超时、重试、恢复、紧急停止和审计，模型输出不能绕过网关直接执行。
3. 受控 ReAct 只保存结构化观察、失败分类、预算、计划差异和引用；服务端检测循环与预算，重规划只产生 proposal，未知状态转人工。

## 安全设计

tenant、principal、actor 和授权上下文由服务端持有。公开 API、日志和 UI 不返回提示、思维链、凭据、原始设备 payload 或敏感证据。Host/CORS、请求体预算、统一错误、安全响应头、日志递归脱敏和非 root 只读容器形成纵深边界。

失败关闭是产品行为：未配置 RAG 返回 503；迁移缺失或生命周期停止导致 not ready；审批拒绝、预算耗尽、循环和未知工具状态停止自动执行或转人工。

## 验证结果

截至 2026-07-24，本地完整后端为 `1029 passed, 1 skipped`，前端为 `24 files / 90 tests passed`，PowerShell 脚本合同 `53 passed`，容器与供应链静态合同 `10 passed`。Liveness HTTP 固定样本 p95 为 `2.499 ms`，RAG 数据集加载 p95 为 `0.114 ms`，均低于 `100 ms` 本地预算。

SQLite 热查询通过 `EXPLAIN QUERY PLAN` 合同使用覆盖排序索引；Alembic 当前 head 为 `20260724_01`，已有升—降—升回归。

## 诚实边界

- `DOCKER_RUNTIME_TESTED=False`：本机没有 Docker CLI，未构建或启动镜像。
- `CI_RUNTIME_TESTED=False`：GitHub Actions 尚未推送或远端执行。
- `NETWORK_ACCESS_TESTED=False`：未验收外部网络路径。
- `REAL_MODEL_PLANNING_TESTED=False`：未运行真实模型自主规划。
- `REAL_DEVICE_PATHS_TESTED=False`：未连接真实防火墙、EDR 或账号系统。

真实 DeepSeek、Embedding、Milvus、Reranker 与安全设备没有授权、没有费用预算、没有调用。离线成功不能替代真实链路验收，SQLite 单实例也不代表生产高可用。

## 后续路线

在授权环境补充 Docker runtime smoke 和远端 CI 证据；将 SQLite 替换为受管数据库并验证备份恢复；接入平台密钥、镜像签名、持续漏洞扫描和网络策略；最后对真实模型与安全设备进行低调用上限、灰度、可回滚的集成验收。

## 答辩材料

`delivery/shieldchain-presentation.pptx` 是 10 页、16:9、可编辑的答辩稿，覆盖问题、架构、闭环、创新、安全、六工作区、验证数据、诚实边界与路线图。
