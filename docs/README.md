# ShieldChain 文档中心

> 文档状态：当前入口（更新于 2026-08-24）。本页与仓库当前代码、根目录 `README.md` 共同定义现行能力；历史计划和验收快照仅用于追溯。

## 当前系统

ShieldChain 已从早期固定钓鱼仿真演进为真实安全数据驱动的多智能体系统：

- Wazuh 接收、持久化并展示真实高风险告警；
- 七个专业角色通过 ReAct 循环按任务自主选择受授权工具；
- 安全运营报告智能体可直接使用事件、告警、漏洞、弱密码四类进程内只读工具；同一 Provider 已通过默认关闭的标准 MCP 2026-07-28 `/mcp` 适配器发布，生产启用必须配置外部 issuer/JWKS、固定 subject 映射、最小 scope 和上游 TLS；
- 新安全运营报告拥有租户化通用运行 ID；历史 JSON 报告明确标记 `legacy_without_run`，不会伪造不存在的轨迹或执行事实；
- 内部运营工具和入站 MCP 调用保存裁剪后的公开审计；恢复时没有终态的调用标记为结果未知，不保存原始载荷、Token 或异常堆栈；
- 外部 MCP Server 只能通过管理员固定 YAML 发现；HTTPS、DNS/CIDR、TLS、重定向、工具映射和 Schema revision 受服务端约束。批准的未过期快照可作为只读 Provider 进入 Broker，并受结果裁剪、预算、并发、速率、熔断、独立凭据和出站审计约束；
- 运营响应规划角色已接入严格候选、服务端编译和版本化计划四表；报告级运行只生成零动作建议，报告保存生成时快照并链接实时处置/ReAct 页面，计划不会自动成为审批或工具执行；
- 案件级计划可由服务端身份授权的操作员接受或拒绝；接受后逐动作创建一对一可信调用并重新经过策略，高风险动作仍需独立审批，未验证依赖不能执行；
- 离线仿真案件已连接执行回执、执行后验证、ReAct 观察、状态查询、失败 revision、人工接管和重启恢复；只有全部必需验证成功才关闭运行，真实设备闭环仍未接入；
- REST 已提供 MCP 状态/目录/peer、Agent Tool/MCP 调用、响应计划、可信调用和 ReAct 的安全公开投影；处置中心明确区分建议、计划接受、工具审批、执行和验证；
- 当前没有真实管理员 RBAC，生产环境只允许上述只读投影，计划、工具、急停和 ReAct REST 写控制保持关闭；
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
10. [可安装 Skills 运行时实施方案](plans/skills-runtime-implementation.md)
11. [MCP、响应规划、智能体工具与安全闭环统一实施方案](plans/mcp-agent-tools-response-safety-loop-implementation.md)

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
