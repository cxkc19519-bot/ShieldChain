# Phase 8 SQLite 查询计划加固报告

## 范围

Task 3 审计阶段 7 六工作区使用的事件、知识、工具、ReAct 和报告聚合查询。本次优化两个存在明确过滤加排序缺口的热路径：

- 事件详情按 `incident_id` 排序全部调查运行，以及按 `simulation_instance_id` 读取最新运行。
- 处置中心按 `tenant_id + run_id` 排序可信工具调用轨迹。

## 索引变更

- 新增 `ix_investigation_run_incident_created(incident_id, created_at, id)`。
- 新增 `ix_investigation_run_simulation_created(simulation_instance_id, created_at, id)`。
- 用 `ix_trusted_tool_call_tenant_run_created(tenant_id, run_id, created_at, id)` 替换较短的 `ix_trusted_tool_call_tenant_run`，避免维护冗余前缀索引。

## 证明

`backend/tests/integration/performance/test_query_indexes.py` 在真实 SQLAlchemy 元数据创建的 SQLite 数据库上执行 `EXPLAIN QUERY PLAN`。三个查询均命中新索引，且计划不包含 `USE TEMP B-TREE`。`20260724_01` 迁移测试执行 upgrade→downgrade→upgrade，并验证降级恢复旧工具索引、升级恢复全部新索引。

完整后端结果：`1011 passed, 1 skipped`。Ruff 通过；唯一警告来自当前工作区不可写 `.pytest_cache`，不影响查询或迁移。

## 边界

本报告证明 SQLite 过滤/排序计划和迁移可逆性，不宣称生产并发吞吐、其他数据库执行计划或云部署容量。固定 HTTP/RAG 延迟基线仍见 `docs/reports/phase8-baseline.md`；真实网络、模型规划和安全设备路径未测试。
