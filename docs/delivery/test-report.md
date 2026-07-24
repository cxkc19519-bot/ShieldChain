# ShieldChain Phase 8 测试报告

## 本地结论（2026-07-24）

- 后端 Ruff：通过。
- 后端 Pytest：`1029 passed, 1 skipped`；跳过项为需明确授权的 live 测试，另有不可写 `.pytest_cache` 警告。
- 前端 Vitest：`24 files passed, 90 tests passed`。
- 前端 TypeScript 与 Vite 生产构建：通过。
- PowerShell 脚本合同：`53 passed`。
- 容器与供应链静态合同：`10 passed`。
- `pip check`：`No broken requirements found`。

## 覆盖范围

后端覆盖配置、HTTP 安全、公开错误、事件闭环、SQLite 仓储、迁移、RAG 解析/检索/拒答/评测、多智能体上下文、工具策略/审批/幂等/恢复、ReAct 预算/循环/接管、查询计划、readiness/version、日志脱敏和交付合同。

前端覆盖六个工作区、API 映射、加载/空/错误状态、请求取消、跨页上下文、键盘焦点、320px 响应式合同、敏感字段不渲染和离线跨页 smoke。

Phase 2–7 smoke 在 Task 4 后通过；Task 6 没有更改业务路径。Alembic `upgrade head → downgrade base → upgrade head` 在既有完整门禁中通过，当前期望 revision 为 `20260724_01`。

## 性能证据

固定 Phase 8 基线：liveness HTTP 25 样本 p50 `1.656 ms`、p95 `2.499 ms`；RAG 数据集加载 p50 `0.099 ms`、p95 `0.114 ms`，预算均为 p95 `100 ms`。SQLite 热查询 `EXPLAIN QUERY PLAN` 合同确认使用覆盖排序索引；这些结果只代表记录机器和固定数据集。

## 未测试边界

- `DOCKER_RUNTIME_TESTED=False`：本机无 Docker CLI，未构建或启动镜像。
- `CI_RUNTIME_TESTED=False`：工作流未推送或远端执行。
- `NETWORK_ACCESS_TESTED=False`：未做外部网络链路验收。
- `REAL_MODEL_PLANNING_TESTED=False`：未运行真实模型自主规划。
- `REAL_DEVICE_PATHS_TESTED=False`：未连接真实防火墙、EDR 或账号系统。

DeepSeek、Embedding、Milvus 和 Reranker live 测试没有授权、没有费用预算、没有执行。静态容器合同不能替代 runtime smoke，依赖一致性不能替代实时 CVE 情报扫描，SQLite 结果不能外推到生产并发数据库。

## 复现

运行 `scripts/verify.ps1` 获取完整本地门禁；运行 `tests/scripts/run-phase8-baseline.ps1` 复测性能；运行 `tests/scripts/run-phase8-container-smoke.ps1` 在 Docker 可用时补充容器运行证据。命令细节和安全清理见 `development-guide.md` 与 `deployment-guide.md`。
