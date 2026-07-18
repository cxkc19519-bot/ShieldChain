# 阶段三：产品级 RAG 设计规格

## 1. 目标与边界

阶段三交付可审计、可评测、可安全降级的知识库与检索增强能力。它必须支持多格式文档、DeepSeek 语义分块、问题改写、BGE-M3、托管 Milvus、BM25 混合召回、BGE-Reranker-v2-m3 重排、引用溯源、权限过滤和无依据拒答。

阶段三不实现多智能体编排、可信工具网关、ReAct、真实安全设备、扫描 PDF OCR、本机大模型、本机 Embedding/Reranker 或 Milvus Standalone。默认测试不得联网或产生云费用。

## 2. 已确认决策

- LLM：DeepSeek API，经现有 `LlmClient` 适配层调用。
- Embedding：云端 BGE-M3，经独立端口调用。
- 向量库：托管 Milvus，经独立端口调用。
- 关键词检索：BM25。
- 融合：默认 RRF，`k=60`；其他加权策略只有在固定评测集证明更好后才能启用。
- 重排：云端 BGE-Reranker-v2-m3，经独立端口调用。
- 本机开发：Windows 直接运行；SQLite 保存控制面元数据，本地受控目录保存原文；外部云能力全部可注入离线替身。
- 后续部署：保留对象存储、正式身份源和 Docker Compose 适配点，不在阶段三提前实现。

## 3. 临时但明确的阶段三假设

云供应商、Endpoint、认证方式和预算尚未获得，因此先完成供应商无关端口、HTTP/Milvus 适配边界、严格配置和默认跳过的 live profile。未获得真实配置前，不得声称云端链路已经验收。

阶段三不引入正式认证系统。API 使用服务器配置的固定本地演示身份，客户端不能提交或覆盖租户；领域与仓储层仍必须以 `tenant_id`、`principal_id`、角色和权限标签执行默认拒绝及跨租户隔离测试。

原文存储在 `data/knowledge/` 下，以服务端生成的 UUID 路径保存，不使用用户文件名拼接路径。默认单文件上限 25 MiB、解压后上限 100 MiB、压缩比上限 100、提取文本上限 2,000,000 字符；均由有界配置控制。

问题改写失败时保留原问题继续检索，并显式标记 `rewrite_degraded=true`。Embedding 或 Milvus 失败时允许显式降级为 BM25；Reranker 失败时保留融合排序并显式标记；任何降级都不能伪造向量或重排分数。

## 4. 数据模型与生命周期

核心实体：

- `KnowledgeBase`：租户、名称、状态、默认敏感级别、版本策略。
- `KnowledgeDocument`：逻辑文档、原始文件名、服务端存储引用、媒体类型、内容哈希、状态和当前版本。
- `DocumentVersion`：版本号、解析状态、分块状态、索引状态、解析器/策略/提示词/模型版本、创建及发布时间。
- `KnowledgeChunk`：稳定 ID、文档版本、顺序、标题路径、页码/表格/工作表位置、文本、Token 数、内容哈希、敏感级别、权限标签、分块来源和降级标记。
- `IndexRecord`：BM25、Embedding、Milvus 和 Reranker 相关的外部引用、版本、状态、错误类别和更新时间。

状态转换由确定性代码控制。知识库和文档支持草稿、发布、回滚、增量更新、重建和删除。删除文档必须以可重试工作流同步删除 BM25、Milvus、缓存和本地原文；部分失败时标记 `delete_pending`，不得对外继续检索。

## 5. 安全文档摄取

首批支持 PDF、DOCX、Markdown、TXT、HTML、CSV、XLSX；扫描 PDF OCR 后置。

摄取顺序固定为：

1. 校验请求身份和知识库权限。
2. 流式计算大小与 SHA-256，不整文件无限制读入内存。
3. 校验扩展名、嗅探媒体类型、允许列表和二者一致性。
4. 对 DOCX/XLSX 等 ZIP 容器检查成员路径、成员数、展开大小和压缩比，拒绝 Zip Slip 与压缩炸弹。
5. 服务端生成存储路径并原子落盘，不执行宏、脚本、外链或活动内容。
6. 在有界超时、页数/单元格/字符预算内解析。
7. 保存结构化内容和可引用元数据；失败时记录安全错误类别，不记录原始敏感内容。

解析器不得访问网络、解析任意本机路径或跟随外部引用。HTML 只提取静态文本结构；CSV/XLSX 采用数据模式，不执行公式。

## 6. 混合分块

确定性规则层先识别标题、章节、段落、列表、表格、代码和日志边界，生成满足 Token 上限的候选块。默认目标 512 tokens、硬上限 768 tokens、相邻文本重叠 64 tokens；表格、代码和日志优先保持语义结构，不盲目截断。

DeepSeek 仅能对候选块提出合并/拆分边界，返回严格 JSON；它不能改写原文、添加事实、修改来源元数据或授予权限。确定性质检必须重新验证：

- 所有输出文本可无损映射到原始解析内容；
- 块顺序、标题路径、页码和表格位置合法；
- 没有遗漏、重复越界、空块或超限块；
- 完整句、表格、代码和日志结构尽量保持；
- 内容哈希与稳定 ID 可复算。

DeepSeek 超时、不可用、限流或格式错误时，规则候选块照常入库，标记 `chunking_mode=rule_degraded` 和失败类别，并允许后续幂等重试升级。必须记录策略、提示词、模型和文档版本。

## 7. 索引与适配器

所有外部能力以端口隔离：`EmbeddingPort`、`VectorIndexPort`、`RerankerPort`、`ChunkBoundaryOptimizer`。适配器必须有有界超时、重试、批量上限、错误分类、脱敏日志和显式费用/调用计数。

BM25 索引必须能在 Windows 本机离线运行并持久重建。中文分词采用可替换 `TokenizerPort`；首版提供确定性中英文安全术语分词器，不把简单空格分词冒充最终中文检索质量。

Milvus 每条向量必须携带 `tenant_id`、`knowledge_base_id`、`document_id`、`document_version_id`、`sensitivity`、`permission_tags`、`published` 等过滤字段。权限过滤必须在向量查询中下推，并在结果装配时再次校验。

## 8. 查询、混合召回与重排

始终保存原问题。DeepSeek 问题改写执行术语规范化、指代消解、上下文补全、安全实体提取和有限多查询扩展，输出严格结构化结果；确定性代码限制查询数量、长度和允许字段。

检索顺序固定为：

1. 鉴权并生成不可扩权的 `AccessScope`。
2. 原问题及合法改写分别执行 BM25 和 BGE-M3/Milvus 召回。
3. 使用 RRF 合并与去重。
4. 再次执行租户、知识库、发布状态、敏感级别和权限标签过滤。
5. 由 BGE-Reranker-v2-m3 交叉编码重排。
6. 装配引用、降级状态和可解释分数来源。

Milvus 不可用时仅返回 BM25 结果并标记 `vector_degraded`；Embedding 失败不得写入假向量；Reranker 失败不得写入假分数。

## 9. 引用、回答约束与拒答

每条检索依据至少包含：知识库、文档、章节/标题路径、页码或结构位置、原文片段、文档版本、BM25/向量/融合/重排可用分数、更新时间和完整性标识。

RAG 文本始终是不可信数据，必须与系统指令隔离。文档中的“忽略指令”“执行命令”或工具调用文本只能作为引用内容，不能改变系统行为或获得工具权限。

高风险安全结论同时检索支持证据和反证。证据不足、相互冲突、已过期或全部无权访问时，返回结构化拒答或请求补充，不允许模型补写不存在的依据。

## 10. API 与最小前端

阶段三提供 `/api/v1/knowledge-bases`、文档上传/版本/发布/删除/重建、检索和评测接口，继续使用统一错误结构与 request ID。上传接口只接受允许格式和受控字段，不能接受本机路径、远程 URL、任意解析器或命令。

最小知识库页面支持：知识库列表、文档上传、状态/降级展示、检索输入、混合召回结果、引用详情和明确拒答。保持淡蓝色、简洁、可访问；完整运营前端仍属于阶段七。

## 11. 评测与可观测性

固定中英文安全知识基准集，至少测量：解析成功率、分块完整性、Recall@K、MRR、nDCG、重排增益、引用正确率、忠实度、拒答准确率、跨语言一致性、P50/P95 延迟、调用次数、估算费用和失败率。

阶段三先建立可重复基线，不伪造不现实的绝对指标。每次检索策略、分词器、提示词、Embedding 或 Reranker 变更必须运行回归并与已提交基线比较；退出门槛中的最低值在真实基准集建立后固化。

日志只记录文档/块/请求标识、大小、耗时、模型、Token/调用计数和错误类别，不记录 API Key、整段原文、完整查询或敏感引用。

## 11.1 Local content-store threat model

The local content root must be owned and writable only by the application account. Static and
operation-boundary checks for reparse points, resolved containment, and file identity are defense
in depth; they do not claim to eliminate races against a local concurrent attacker who can modify
the root or any ancestor. Such write access is outside the Phase 3 threat model. A future
object-store adapter or Windows handle-based adapter should provide the stronger production
boundary if that attacker is in scope.

## 12. 验收与退出门槛

- 七种格式都有成功、边界和恶意输入测试；OCR 缺失被明确报告。
- DeepSeek 分块正常、超时、限流和畸形输出均可复现；规则降级可检索且可重试升级。
- BM25、向量、RRF、权限过滤、重排顺序可观察；各云服务失败均按设计降级或停止。
- 跨租户、越权、路径穿越、Zip Slip、压缩炸弹、提示注入和密钥泄漏测试通过。
- 删除后本地原文、SQLite 控制面、BM25、Milvus 和缓存均不可检索；部分失败可重试。
- 引用字段完整；无依据、冲突、过期和无权限场景正确拒答。
- 默认完整测试离线且零云费用；live 测试只能显式启用并设置调用/费用上限。
- Windows 本机启动、阶段三 smoke、后端/前端测试、Ruff、ESLint、类型检查、构建、迁移往返和固定 RAG 评测全部通过。
- 相关规格、操作说明、开发日志和路线图同步更新后，才可进入阶段四。
