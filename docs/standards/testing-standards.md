# 测试标准

> 文档状态：当前参考（更新于 2026-08-08）。旧仿真和视频测试仅属于历史阶段，不纳入当前功能验收。

## 分层

- 单元测试：领域规则、参数校验、分块、工具选择、降级和格式转换；
- 集成测试：Wazuh 接收、运营报告、RAG 持久化、API 合同和数据库迁移；
- 前端测试：路由、加载/错误/空状态、中文公开摘要和敏感字段边界；
- 配置测试：基础、服务器和本地模型 Compose 合并结果；
- 实时测试：仅在显式授权、预算和隔离环境下运行模型、Milvus、Embedding、Reranker 与安全设备链路。

## 必须验证

- 工具调用失败不能被解释为无风险或成功；
- 模型结构化输出无效时安全降级；
- 知识库、会话和报告重启后仍存在；
- 删除操作同步清理关联数据和索引；
- 前端不渲染私有提示词、思维链、凭据和原始载荷；
- 四类 MCP 保持只读，响应建议不触发处置；
- Wazuh Webhook 具备鉴权、幂等、最小等级和关联窗口测试。

## 当前关键命令

```powershell
conda run -n ShieldChain python -m pytest `
  backend/tests/integration/api/test_operations_report.py `
  backend/tests/integration/api/test_wazuh_ingestion.py `
  backend/tests/unit/operations/test_operations_report_service.py `
  backend/tests/unit/rag/test_local_semantic_chunking.py -q

npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
```

全量测试若仍包含已退役功能合同，应先更新或移除对应测试，不能通过恢复旧产品功能来掩盖文档与代码的不一致。
