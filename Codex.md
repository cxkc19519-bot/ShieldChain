# 盾链智御项目工作指引

## 项目目标

构建“盾链智御——基于可信工具调用与多智能体协同的网络安全运营超级智能体”。所有工作优先满足比赛 PDF 的基础任务、RAG 进阶任务和超级智能体挑战任务。

## 开始工作前必读

1. 产品范围：`docs/requirements/product-requirements.md`
2. 已确认设计：`docs/superpowers/specs/2026-07-13-shield-chain-superagent-design.md`
3. 系统架构：`docs/architecture/system-design.md`
4. RAG 标准：`docs/architecture/rag-design.md`
5. 上下文工程：`docs/architecture/context-engineering.md`
6. 可信工具规范：`docs/architecture/trusted-tool-calling.md`
7. 开发阶段：`docs/plans/development-roadmap.md`
8. 编码、安全、测试与文档标准：`docs/standards/`
9. 本机开发说明：`docs/operations/local-development.md`
10. 阶段 4 设计：`docs/superpowers/specs/2026-07-20-phase-4-multi-agent-context-design.md`
11. 阶段 4 实施计划：`docs/superpowers/plans/2026-07-20-phase-4-multi-agent-context.md`

## 工作规则

- 采用垂直切片、小步闭环；一次只推进当前阶段中的一个可验证事项。
- 修改前明确验收标准；功能或缺陷修改优先补充测试。
- 每次修改后运行与风险相称的测试，未经验证不得声称完成。
- DeepSeek、Embedding、Reranker、Milvus 和未来深信服平台均通过适配层接入。
- LLM 不得绕过可信工具网关，不得执行模型生成的任意 Shell 或代码。
- API Key、密码、令牌和真实敏感数据只通过环境变量或密钥服务提供，不得写入代码、日志、测试夹具或版本库。
- 智能体共享结构化案件上下文，同时保有最小必要的角色私有上下文；跨智能体交接必须包含证据引用。
- 原始证据不可由模型覆盖；模型结论、事实、假设和工具结果必须分开保存。
- 遇到云服务失败必须显式降级或停止，不得伪造成功结果。
- 不进行与当前阶段无关的重构或功能扩张。

## 开发日志

- 只要当天发生项目开发工作，结束前必须创建或更新 `development-logs/YYYY-MM-DD.md`。
- 日志必须记录：完成事项、修改文件、验证命令与结果、遗留问题、风险和下一步。
- 没有开发活动的日期不创建空日志。
- 当前待办以最新开发日志和 `docs/plans/development-roadmap.md` 为准。

## 阶段完成门槛

功能验收通过、自动化测试通过、安全检查通过、相关文档和当日日志更新后，才可进入下一阶段。

