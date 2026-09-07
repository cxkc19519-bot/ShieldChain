# BGE/Milvus/Reranker/Qwen 完整链路预检（2026-09-04）

## 结论

当前代码和固定评测入口已准备，但本机不具备完整模型链路的启动条件，因此本次没有生成“完整模型通过”的虚假结论。2026-07-28 报告是当时版本的历史快照，不能替代当前版本复验。

## 实测环境

| 检查项 | 当前结果 | 影响 |
| --- | --- | --- |
| Docker CLI/Engine | 未安装或不在 PATH | 无法启动本机 Milvus，也无法校验/运行 Qwen vLLM Compose |
| BGE-M3 权重 | `data/models/bge-m3/config.json` 不存在 | 本地 Embedding 服务不能就绪 |
| BGE Reranker 权重 | `data/models/bge-reranker-v2-m3/config.json` 不存在 | 本地重排服务不能就绪 |
| 本地端口 | 8000、8001、19530、9091 均未监听 | 后端、模型服务和 Milvus 当前未运行 |
| GPU | 1 × RTX 3050 Ti Laptop，4,096 MiB | 不满足当前 Qwen3-30B FP8 双 GPU 配置 |
| Qwen Compose 要求 | `pipeline-parallel-size=2`，文档目标为 2 × 24 GB GPU | 必须移到目标双 GPU 服务器运行 |

## 已完成的替代验证

- 本地模型 HTTP 边界、BGE 1024 维校验、Milvus 适配器、失败降级和相关合同均由离线测试覆盖；
- 12 条 RAG 固定集真实探测当前依赖，确认向量和重排失败会记录并熔断，不伪造分数；
- 8 条助手固定集在生成离线时 8/8 通过，证明抽取式安全降级和引用溯源可用；
- 未下载模型、未抢占 GPU、未终止其他进程。

## 目标服务器复验步骤

1. 确认 Docker、两张 24 GB GPU 和空闲显存，不影响其他团队任务；
2. 准备 BGE-M3、BGE-Reranker-v2-m3 和 Qwen3-30B-A3B-Instruct-2507-FP8 权重；
3. 启动 Milvus、本地 BGE 服务和 Qwen/vLLM，确认健康端点；
4. 运行 `scripts/run_rag_evaluation.py`，要求结果无 `vector_degraded`/`reranker_degraded` 且失败率不超过 0.05；
5. 运行不带 `--offline` 的 `scripts/run_assistant_evaluation.py`，确认知识题状态为 `grounded`，再增加 Qwen 声明级事实支持率评测；
6. 将新结果保存为独立报告，不覆盖降级基线或历史快照。
