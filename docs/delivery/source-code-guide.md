# ShieldChain 源代码说明

## 仓库入口

- `backend/src/shieldchain/main.py`：FastAPI factory、中间件、异常映射、依赖装配与生命周期。
- `frontend/src/main.tsx`：React 启动入口；`frontend/src/app` 包含应用壳、路由和跨页运行上下文。
- `backend/migrations`：Alembic schema 历史；当前期望 head 为 `20260724_01`。
- `tests/scripts`：阶段 smoke、脚本安全合同、性能基线和可选容器验收。
- `compose.yaml`：迁移、后端、前端和具名卷的单机部署拓扑。

## 后端模块

- `api`：health、incidents、knowledge、agents、tools、react 六组公开路由，只返回白名单投影。
- `core`：严格配置、HTTP 安全、request ID、结构化日志、公开错误模型。
- `db`：SQLAlchemy engine/session、Base 和迁移共用元数据。
- `incidents`：固定钓鱼场景、仓储、调查状态机、后台运行器、查询聚合与仿真防火墙。
- `rag`：解析、分块、索引、混合检索、重排、引用、拒答和固定评测。
- `agents`：角色、任务、tenant-bound 协作、上下文交接和公开轨迹。
- `tools`：注册、策略、审批、幂等执行、审计、恢复和仿真适配器。
- `react`：观察、失败分类、预算、循环检测、重规划、验证和人工接管。
- `quality`：Phase 8 性能预算、测量和报告模型。

## 前端模块

`frontend/src/features` 按产品工作区拆分：`dashboard`、`investigation`、`agents`、`knowledge`、`tools`、`reports`。每个工作区把 API、类型、页面、样式和测试放在同一目录。共享请求逻辑位于 `src/api`，通用状态组件位于 `src/components`，全局设计 token 位于 `src/styles`。

六条页面路由分别为 `/`、`/events`、`/agents`、`/knowledge`、`/response`、`/reports`。URL 和 sessionStorage 只保存公开资源 ID 与显示偏好；tenant、principal、权限、凭据和内部 payload 保留在服务端。

## 请求执行路径

请求先经过安全响应头、request ID、请求体上限、Host 与 CORS 控制，再进入路由。写操作在服务端解析 tenant/principal 上下文，经过确定性策略和 revision/CAS；工具变更必须进入受信工具网关，ReAct 重规划只生成 proposal，不能绕过审批执行。

事件数据、工具调用、ReAct 轨迹和报告读模型使用 SQLite 持久化；RAG 默认是未配置服务并返回 503，只有测试或明确装配的离线适配器会提供结果。

## 修改约束

新增 API 时必须同步公开模型、错误语义、tenant 负向测试和前端类型。新增表或索引必须增加可逆迁移并执行升—降—升。新增外部能力必须先定义 port/adapter，禁止从业务模块直接读取密钥或访问网络。新增页面必须覆盖加载、空、错误、取消、键盘和敏感字段不渲染。

完整开发和验证命令见 `development-guide.md`，测试证据见 `test-report.md`，部署边界见 `deployment-guide.md`。
