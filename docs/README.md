# ShieldChain 文档中心

> 文档状态：当前入口（更新于 2026-08-08）。本页与仓库当前代码、根目录 `README.md` 共同定义现行能力；历史计划和验收快照仅用于追溯。

## 当前系统

ShieldChain 已从早期固定钓鱼仿真演进为真实安全数据驱动的多智能体系统：

- Wazuh 接收、持久化并展示真实高风险告警；
- 七个专业角色通过 ReAct 循环按任务自主选择受授权工具；
- 安全运营报告智能体可使用事件、告警、漏洞、弱密码四类只读 MCP 工具；
- RAG 支持持久化知识库、语义分块、混合召回、向量检索和重排；
- 智能助手基于知识库与历史报告回答问题并持久化对话记忆；
- 可通过外部 DeepSeek API 或本地 vLLM `Qwen3-30B-A3B-Instruct-2507-FP8` 提供模型能力；
- 模型只负责分析、规划和建议，真实处置仍受策略、审批、可信工具网关与执行后验证约束。

## 阅读顺序

1. [产品需求](requirements/product-requirements.md)
2. [系统设计](architecture/system-design.md)
3. [多智能体设计](architecture/multi-agent-design.md)
4. [RAG 设计](architecture/rag-design.md)
5. [可信工具调用](architecture/trusted-tool-calling.md)
6. [Windows 本地开发](operations/local-development.md)
7. [Wazuh 告警接入](operations/wazuh-read-only-ingestion.md)
8. [部署手册](delivery/deployment-guide.md)
9. [开发路线](plans/development-roadmap.md)

## 文档状态约定

- **当前参考**：与现行代码和部署方式保持一致。
- **历史验收快照**：保留当时环境、命令与结论，不代表今天仍是同一边界。
- **历史计划/设计档案**：记录阶段性决策；若与当前参考冲突，以当前参考和代码为准。
- **已退役**：对应功能或交付物已删除，仅保留追溯说明。

## 当前部署边界

- Docker、Wazuh/OpenSearch 与 ShieldChain 服务已在学校服务器路径 `/home/user/jhk` 下进行实际部署和运行检查。
- 本地 30B-A3B vLLM 配置与镜像已就绪；模型权重下载和服务启动取决于代理链路与两张 RTX 4090 的可用显存。
- 服务器为共享 GPU 环境，不得终止、修改或抢占其他用户进程；长期服务应先完成资源协调。
- `.env`、数据库、真实告警、模型权重、API Key 和令牌不得提交到版本库。

## 已退役内容

- 固定钓鱼模拟攻击入口及其前端调查页面不再作为现行产品能力。
- Remotion 视频工程、比赛 MP4 成品及相关交付测试已从仓库删除。
- 旧阶段 smoke、计划或报告中出现上述内容时，仅代表历史状态。
