# ShieldChain 源代码说明

> 文档状态：当前参考（更新于 2026-08-24）。

## 后端

入口文件：`backend/src/shieldchain/main.py`；前端入口：`frontend/src/main.tsx`。

- `backend/src/shieldchain/main.py`：应用装配、路由和生命周期；
- `backend/src/shieldchain/agents/`：七角色领域模型、上下文、交接、运行时和轨迹；
- `backend/src/shieldchain/operations/`：安全运营报告智能体、ReAct 协作、跨域证据投影、结构化推理链、闭环状态和只读 MCP；
- `backend/src/shieldchain/wazuh/`：Wazuh 告警模式、持久化和服务；
- `backend/src/shieldchain/rag/`：文档、分块、检索、Milvus 和评测；
- `backend/src/shieldchain/assistant/`：会话、摘要记忆、RAG 回答和本地存储；
- `backend/src/shieldchain/tools/`：可信工具注册、策略、仓储和执行边界；
- `backend/migrations/`：数据库迁移；
- `tests/scripts/`：离线 smoke、MCP conformance、容器静态合同和最终门禁脚本；

## 前端

- `frontend/src/app/`：应用壳、路由和公开运行上下文；
- `frontend/src/features/dashboard/`：运营总览；
- `frontend/src/features/operations/`：安全运营报告、结构化推理链、跨域证据覆盖和闭环回放；
- `frontend/src/features/alerts/`：实时告警；
- `frontend/src/features/knowledge/`：知识库和分块；
- `frontend/src/features/reports/`：历史报告与操作入口；
- `frontend/src/features/assistant/`：持久化智能助手；
- `frontend/src/features/agents/`、`tools/`：公开协作/推理轨迹和可信控制。

当前主要页面包括 `/dashboard`、`/operations-report`、`/alerts`、`/knowledge`、`/reports`、`/assistant`，以及受控轨迹和工具页面。已删除的 `/events` 固定仿真入口不再属于当前路由合同。

## 部署文件

- `app.py`：Windows 一键启动；
- `compose.yaml`：基础容器；
- `tests/scripts/`：脚本级部署与验收合同测试；
- `compose.server.yaml`：服务器持久化覆盖；
- `compose.local-llm.yaml`：双 GPU Qwen/vLLM；
- `scripts/wazuh/custom-shieldchain`：Manager 侧告警转发。

## 数据目录

运行生成的 `.env`、`backend/data/`、数据库、知识原文、助手会话、Wazuh 告警和模型缓存都不属于源代码交付，不得提交。
