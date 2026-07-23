# 盾链智御（ShieldChain）

盾链智御是一个面向网络安全运营的智能体研究项目。当前代码提供 Windows 本地可运行的 FastAPI/React 基础、确定性钓鱼事件闭环、产品级 RAG，以及租户隔离的多智能体上下文、结构化交接、确定性编排、只读协作轨迹 API 和智能体工作台。默认配置使用 SQLite 和离线替身；真实 DeepSeek、Embedding、Milvus、Reranker 与安全设备尚未授权和接线，知识 API 默认失败关闭，响应角色只生成 proposed actions，不会伪造云调用或工具执行成功。

## 前置条件

- Windows PowerShell 5.1 或 PowerShell 7。
- Python `>=3.12,<3.15`，可通过 `py` 启动器调用。
- 当前 Node.js LTS（包含 `npm.cmd`）。
- 不需要 Docker。

## 本地安装

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".\backend[test]"
npm ci --prefix frontend
Copy-Item .env.example .env
```

`.env` 仅用于本机配置，绝不能提交到版本库。默认离线开发不需要填写真实 DeepSeek 密钥。

## 启动与验证

```powershell
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase2-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase3-smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase4-smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

前端地址为 `http://127.0.0.1:5173`，后端地址为 `http://127.0.0.1:8000`。阶段 2 smoke 验证事件闭环；阶段 3 smoke 验证离线 RAG；阶段 4 smoke 在临时 SQLite 上继续验证迁移、离线多智能体编排、原子提交和公开轨迹泄漏边界。`verify.ps1` 执行完整测试、构建、迁移往返、固定 RAG 评测、脚本契约和阶段 3/4 smoke，不产生云调用或费用。

## 文档导航

- [产品需求](docs/requirements/product-requirements.md)
- [系统设计](docs/architecture/system-design.md)
- [开发路线](docs/plans/development-roadmap.md)
- [Windows 本地开发](docs/operations/local-development.md)
- [安全标准](docs/standards/security-standards.md)

任何 API Key、密码、令牌、真实告警或客户数据都不得写入代码、测试夹具、日志或版本库。
