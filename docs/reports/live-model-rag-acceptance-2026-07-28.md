# 真实模型规划与本地 RAG 链路验收（2026-07-28）

## 验收范围

本次验收覆盖 Windows 本机的真实模型与真实检索依赖，不把离线替身结果当作真实链路结论：

- DeepSeek `deepseek-v4-flash`：受控安全处置规划；
- 本机 BAAI `bge-m3`：1024 维向量生成；
- 本机 Milvus：向量索引与检索；
- 本机 BAAI `bge-reranker-v2-m3`：候选文档重排序；
- 已持久化的“安全垂直知识库（2026）”中的 MITRE ATT&CK 文档。

## 实测结论

| 检查项 | 实测结果 | 结论 |
| --- | --- | --- |
| DeepSeek 受控规划 | 返回模型 `deepseek-v4-flash`，决策 `proceed`，摘要“确认威胁，按策略阻断目的 IP。” | 通过 |
| 向量模型 | `/v1/embeddings` 返回 1024 维向量 | 通过 |
| 重排序模型 | 正相关文档分数 `0.99839`，无关文档分数 `0.04416` | 通过 |
| 本地设备 | Embedding 与 Reranker 均加载成功，设备为 `cuda` | 通过 |
| RAG 端到端 | 重建 ATT&CK 文档索引后，`/api/v1/rag/retrieval` 返回 3 个命中、向量分数与重排序分数，且无 degradation | 通过 |
| 调查闭环接线 | `INC-2026-0001` 完成确定性研判、真实 RAG 检索、DeepSeek 规划并通过可信仿真网关完成验证 | 通过 |

## 安全边界

DeepSeek 只接收经过服务端裁剪的研判、最多五条证据摘要和受控 RAG 摘要，并只允许输出 `proceed` 或 `manual_review`。它不能生成命令、凭据、工具、目标或动作。

即使模型选择 `proceed`，也只能继续确定性规则已批准的“通过可信工具网关阻断当前事件目的 IP”；模型无权扩大权限。模型选择 `manual_review` 时，工作流会从 `action_planned` 进入 `needs_review`，不提交自动处置。

## 启动与复验

运行 `python app.py --no-browser` 会启动：Milvus、`127.0.0.1:8001` 的本机模型服务、后端和前端。模型文件默认位于 `data/models`，可用 `SHIELDCHAIN_RAG_MODELS_ROOT` 覆盖。首次推理会加载模型；具备 CUDA 时自动使用 GPU，否则回退 CPU。

重建旧文档索引后，知识库查询应同时显示向量和重排序分数；任一服务不可用时，RAG 会显式记录 `vector_degraded` 或 `reranker_degraded`，不会把降级结果冒充为真实向量/重排序结果。

## 未覆盖范围

本报告不等同于公有云 Milvus、生产数据库、真实安全设备、Docker 运行时、远端 CI 或生产并发验收；这些项目仍需在各自授权环境单独验证。