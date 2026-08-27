# ShieldChain 测试报告

<!-- ShieldChain acceptance boundary flags: these are intentionally explicit until the corresponding external environments are available. -->
DOCKER_RUNTIME_TESTED=False
NETWORK_ACCESS_TESTED=False
REAL_MODEL_PLANNING_TESTED=False
REAL_DEVICE_PATHS_TESTED=False
CI_RUNTIME_TESTED=False

> 文档状态：当前验证摘要（更新于 2026-08-27）。Phase 8 历史报告保留当时结果，本页记录当前功能相关验证。

## 已执行验证

Phase 8 历史基线：`1037 passed, 1 skipped`；前端历史基线：`90 tests passed`。这些数字保留用于交付追溯，当前功能验证结果见下方。

- 智能体、运营报告、ReAct/RAG 关键后端回归：8 个通过；
- 交付文档与最终交付合同：6 个通过；
- 前端全量：26 个测试文件、95 个测试通过；
- TypeScript 类型检查、ESLint 与 Vite 生产构建通过；
- `compose.yaml + compose.server.yaml` 配置检查通过；
- `compose.yaml + compose.local-llm.yaml` 配置检查通过；
- 交付清单支持区分 `available` 与 `planned`，并检查未完成的 PPT、视频、ZIP 和校验和不会提前出现在仓库；
- 当前不宣称最终交付 smoke 已通过，最终版本冻结后需要重新执行完整门禁。

## 全量套件说明

后端全量执行曾得到 1019 个通过、1 个跳过，同时仍有旧固定仿真接口、旧 Phase 7 合同和已删除视频工程产生的过时失败。视频工程测试已删除；其余旧仿真合同应在后续清理中更新或归档，不能通过恢复已退役产品功能来追求表面全绿。

## 实时链路状态

- Wazuh/OpenSearch 与 ShieldChain Docker 服务已在学校服务器环境实际运行；
- vLLM 镜像和 Compose 配置已验证；
- Qwen3-30B-A3B 权重下载和推理服务启动尚受共享 GPU 可用性约束；
- 2026-07-28 的 DeepSeek 与真实 RAG 验收见历史快照报告；
- 真实处置设备链路仍未进行授权执行验收。

## 安全结论

- 测试不应输出或提交真实密钥、告警和客户数据；
- 只读 MCP 与可信处置网关必须分别测试；
- 模型失败、工具失败和 RAG 降级必须形成明确公开状态；
- 任何实时模型或安全设备测试都需要显式开关、预算、隔离数据和人工批准。
