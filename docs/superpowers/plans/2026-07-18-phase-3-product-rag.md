# Phase 3 Product-Grade RAG Implementation Plan

## Goal

按 `docs/superpowers/specs/2026-07-18-phase-3-product-rag-design.md` 交付产品级、可审计、可评测、可显式降级的 RAG。每个任务是独立可验收的小闭环；默认测试离线、无云费用。

## Global Constraints

- Python 3.12-3.14、FastAPI、SQLAlchemy、Alembic、SQLite；API 使用 `/api/v1`、统一错误结构和 request ID。
- React 19、TypeScript、Vite；Windows 本机直接运行。
- DeepSeek、Embedding、Milvus、Reranker 全部经端口/适配器接入；默认测试不得联网。
- 首批格式严格为 PDF、DOCX、Markdown、TXT、HTML、CSV、XLSX；扫描 PDF OCR 后置并显式报告。
- 原问题永久保留；改写失败使用原问题并标记降级。
- BM25 + BGE-M3/Milvus 使用 RRF `k=60` 融合，再权限过滤，再 BGE-Reranker-v2-m3 重排。
- RAG 内容是不可信数据，不能覆盖系统指令或获得工具权限。
- 客户端不能提交租户身份、本机路径、远程 URL、任意解析器、Shell 或代码。
- 默认单文件 25 MiB、展开 100 MiB、压缩比 100、提取 2,000,000 字符；所有限制可配置且有硬上界。
- 测试先行；每个任务只跑覆盖自身的测试，阶段出口才跑完整验证和 smoke。
- 每个任务完成后更新 `development-logs/YYYY-MM-DD.md`，不夹带阶段四功能。

## Task 1: RAG Core Domain, Access Scope, and External Ports

**Files**

- Add `backend/src/shieldchain/rag/__init__.py`
- Add `backend/src/shieldchain/rag/domain.py`
- Add `backend/src/shieldchain/rag/ports.py`
- Add `backend/tests/unit/rag/test_domain.py`
- Add `backend/tests/unit/rag/test_ports.py`

**Acceptance**

- 定义知识库、文档、版本、块、索引状态、引用、检索降级和结构化拒答的不可变领域类型。
- `AccessScope` 强制 tenant、principal、角色、敏感级别和权限标签，默认拒绝，不能由检索结果扩权。
- 定义内容存储、解析器、分块优化、Embedding、向量索引、BM25、Reranker、时钟和仓储端口及分类错误。
- 严格校验 ID、枚举、非空文本、UTC 时间、分数范围、块顺序和引用字段。
- 仅领域/端口，无数据库、API、云 SDK 或阶段四代码。

**Gate**

- 新测试 RED 后 GREEN；`pytest backend/tests/unit/rag -q`；`ruff check backend`。

## Task 2: SQLite Control Plane and Alembic Migration

**Files**

- Add `backend/src/shieldchain/rag/persistence.py`
- Add `backend/src/shieldchain/rag/repositories.py`
- Update `backend/src/shieldchain/db/session.py`
- Add `backend/migrations/versions/*_add_rag_control_plane.py`
- Add `backend/tests/unit/rag/test_persistence.py`
- Add `backend/tests/integration/rag/test_repositories.py`

**Acceptance**

- 持久化 knowledge base、document、version、chunk、ACL/index state；外键、唯一约束、索引和 UTC 边界明确。
- 跨租户查询默认不可见；文档版本、发布、回滚和 `delete_pending` 状态转换原子化。
- 重复内容和幂等请求不会重复创建版本或块。
- Alembic upgrade/downgrade/upgrade 往返通过，迁移不导入可变应用常量。

## Task 3: Secure Intake and Local Content Store

**Files**

- Add `backend/src/shieldchain/rag/intake.py`
- Add `backend/src/shieldchain/rag/storage.py`
- Update `backend/src/shieldchain/core/config.py`
- Add `backend/tests/unit/rag/test_intake.py`
- Add `backend/tests/integration/rag/test_storage.py`

**Acceptance**

- 流式大小/SHA-256、扩展名和媒体类型一致性、UUID 路径、原子写入、受控删除。
- 拒绝路径穿越、远程 URL、Zip Slip、压缩炸弹、超限成员/大小/字符和不允许格式。
- DOCX/XLSX 容器只检查不执行；日志不含原文、密钥或用户路径。
- 所有失败不留下半文件；删除幂等。

## Task 4: Seven Deterministic Document Parsers

**Files**

- Add `backend/src/shieldchain/rag/parsing.py`
- Add parser modules under `backend/src/shieldchain/rag/parsers/`
- Update `backend/pyproject.toml`
- Add fixed fixtures under `backend/tests/fixtures/rag/`
- Add `backend/tests/unit/rag/test_parsing.py`

**Acceptance**

- PDF、DOCX、MD、TXT、HTML、CSV、XLSX 解析为统一结构，保留标题、页码、表格/工作表和来源位置。
- HTML 不访问外链；XLSX `data_only` 且不执行公式；扫描 PDF 返回明确 OCR-required 状态。
- 页数、行数、单元格、字符和解析时间有界；畸形文件受控失败。
- 依赖使用固定兼容范围并记录许可证/安全理由。

## Task 5: Deterministic Chunking and Quality Validation

**Files**

- Add `backend/src/shieldchain/rag/chunking.py`
- Add `backend/src/shieldchain/rag/tokenization.py`
- Add `backend/tests/unit/rag/test_chunking.py`

**Acceptance**

- 结构预切分覆盖标题、段落、列表、表格、代码和日志；目标 512、硬上限 768、重叠 64 tokens。
- 稳定 ID 和内容哈希可复算；块能无损映射原文，顺序/来源/页码完整。
- 中英文、超长句、表格、日志、代码、空白和重复内容有固定测试。

## Task 6: DeepSeek Semantic Boundary Optimization with Rule Fallback

**Files**

- Add `backend/src/shieldchain/rag/semantic_chunking.py`
- Reuse `backend/src/shieldchain/llm/ports.py`
- Add `backend/tests/unit/rag/test_semantic_chunking.py`
- Add mocked adapter tests under `backend/tests/integration/rag/`

**Acceptance**

- DeepSeek 只能返回严格 JSON 边界，不得改写原文或来源。
- 确定性校验拒绝遗漏、重复、越界、乱序、伪造元数据和超限结果。
- 超时、限流、不可用、畸形 JSON 自动回退规则块并记录 degraded、模型/提示词/策略版本，可幂等重试升级。

## Task 7: BM25, Embedding, Milvus, and Index Lifecycle

**Files**

- Add `backend/src/shieldchain/rag/bm25.py`
- Add `backend/src/shieldchain/rag/embedding.py`
- Add `backend/src/shieldchain/rag/milvus.py`
- Add `backend/src/shieldchain/rag/indexing.py`
- Add unit/integration tests under `backend/tests/{unit,integration}/rag/`

**Acceptance**

- 确定性中英文 Tokenizer 和可重建 BM25；测试证明中文不是纯空格分词。
- BGE-M3 批量、维度、超时、限流、畸形向量和费用计数严格校验。
- Milvus Schema 含全部权限/版本过滤字段，查询下推租户和 ACL。
- 新增、更新、发布、回滚、删除、重建可重试；Embedding/Milvus 失败不伪造索引。
- live tests 默认跳过并要求显式开关及调用上限。

## Task 8: Query Rewrite and Hybrid Retrieval

**Files**

- Add `backend/src/shieldchain/rag/rewrite.py`
- Add `backend/src/shieldchain/rag/retrieval.py`
- Add `backend/tests/unit/rag/test_rewrite.py`
- Add `backend/tests/unit/rag/test_retrieval.py`

**Acceptance**

- 保存原问题；改写严格限制数量/长度/字段，覆盖术语、指代、上下文和安全实体。
- 改写失败使用原问题并标记 `rewrite_degraded`。
- BM25 与向量多查询结果以 RRF `k=60` 合并、稳定去重；权限在查询下推及结果装配双重校验。
- Milvus 不可用时显式 BM25-only，不伪造向量分数。

## Task 9: Reranking, Citations, Refusal, and Evaluation Harness

**Files**

- Add `backend/src/shieldchain/rag/reranking.py`
- Add `backend/src/shieldchain/rag/citations.py`
- Add `backend/src/shieldchain/rag/answering.py`
- Add `backend/src/shieldchain/rag/evaluation.py`
- Add fixed bilingual dataset under `backend/tests/fixtures/rag/evaluation/`
- Add corresponding tests.

**Acceptance**

- BGE-Reranker-v2-m3 严格校验批量和分数；失败保留融合顺序并标记降级。
- 引用包含设计规格全部字段且片段来自原块。
- 无依据、冲突、过期、无权限和提示注入场景结构化拒答。
- 评测计算 Recall@K、MRR、nDCG、重排增益、引用正确率、拒答准确率、延迟/费用/失败率；结果可重复并生成机器可读报告。

## Task 10: Knowledge API and Minimal Knowledge Page

**Files**

- Add `backend/src/shieldchain/api/knowledge.py`
- Add `backend/src/shieldchain/rag/schemas.py`
- Update `backend/src/shieldchain/main.py`
- Add `frontend/src/features/knowledge/*`
- Update router and tests.

**Acceptance**

- 提供知识库、上传、版本、发布、回滚、删除、重建、检索和评测 API；严格 snake_case Schema。
- 本地演示身份由服务端配置，客户端无法覆盖 tenant；跨租户和任意路径/URL 输入测试为拒绝。
- 页面展示文档/索引/降级状态、检索结果、引用和拒答，保持淡蓝简洁且可访问。

## Task 11: Windows Phase 3 Gate, Operations, and Exit Review

**Files**

- Add `tests/scripts/run-phase3-smoke.ps1`
- Update `scripts/verify.ps1` and contract tests
- Update `docs/operations/local-development.md`
- Update `docs/plans/development-roadmap.md`
- Update current development log.

**Acceptance**

- 临时 SQLite、本地内容目录和离线云替身完成上传→解析→分块→索引→改写→混合检索→重排→引用/拒答 smoke，并清理进程、端口和临时数据。
- live profile 单独检查配置但默认不调用；输出明确说明哪些云链路尚未实测。
- 完整后端/前端、Ruff、ESLint、类型检查、构建、迁移往返、安全测试、RAG 评测、脚本契约和 smoke 全部通过。
- 更新路线图为阶段三已完成后才能进入阶段四。

## Fast Execution Policy

- 同一时间只允许一个实现智能体修改工作区；只读研究和复审可并行。
- 每个任务先跑聚焦测试，不重复完整全套；任务 3、6、7、8、9、10 完成后跑相关跨模块回归。
- Task 11 才运行完整门禁。发现 Critical/Important 时一次性集中修复并复审。
- 每个任务独立提交，便于定位回退；不推送、不合并，除非用户明确要求。
