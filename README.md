# 盾链智御（ShieldChain）

盾链智御是一个面向网络安全运营的智能体研究项目。当前代码提供 Windows 本地可运行的 FastAPI/React 基础、确定性钓鱼事件闭环、产品级 RAG、租户隔离的多智能体编排，以及可信工具注册、策略、审批、幂等执行、验证、恢复、紧急停止、公开轨迹 API 和最小处置中心。默认配置使用 SQLite 和离线替身；真实 DeepSeek、Embedding、Milvus、Reranker 与安全设备尚未授权和接线，知识 API 默认失败关闭，真实设备路径不会被离线成功结果替代。

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
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase5-smoke.ps1
```

前端地址为 `http://127.0.0.1:5173`，后端地址为 `http://127.0.0.1:8000`。阶段 2–4 smoke 分别验证事件闭环、离线 RAG 和多智能体编排；阶段 5 smoke 验证策略、审批拒绝、幂等执行、未知结果失败关闭、验证恢复和紧急停止。`verify.ps1` 执行完整测试、构建、迁移往返、固定 RAG 评测、脚本契约和阶段 5 smoke，不联网、不访问真实设备、不产生费用。

## 文档导航

- [产品需求](docs/requirements/product-requirements.md)
- [系统设计](docs/architecture/system-design.md)
- [开发路线](docs/plans/development-roadmap.md)
- [Windows 本地开发](docs/operations/local-development.md)
- [安全标准](docs/standards/security-standards.md)

任何 API Key、密码、令牌、真实告警或客户数据都不得写入代码、测试夹具、日志或版本库。
