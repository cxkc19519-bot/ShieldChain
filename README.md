# 盾链智御（ShieldChain）

盾链智御是一个面向网络安全运营的智能体研究项目。当前代码提供 Windows 本地可运行的 FastAPI/React 基础、确定性钓鱼事件闭环、产品级 RAG、租户隔离的多智能体编排、可信工具网关，以及受预算约束的 ReAct 观察—分类—重规划—验证闭环和人工接管 API。默认配置使用 SQLite 和离线替身；真实 DeepSeek、Embedding、Milvus、Reranker、模型自主规划与安全设备尚未授权和接线，离线成功结果不替代真实链路验收。

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
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase2-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase3-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase4-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase5-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase6-smoke.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase7-smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase8-baseline.ps1
powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase8-container-smoke.ps1
```

前端地址为 `http://127.0.0.1:5173`，后端地址为 `http://127.0.0.1:8000`。阶段 2–5 smoke 依次验证事件闭环、离线 RAG、多智能体编排和可信工具；阶段 6 验证受预算约束的 ReAct 闭环；阶段 7 验证运营总览、事件调查、智能体、知识库、处置、报告与审计六个工作区的离线跨页合同。`verify.ps1` 执行完整后端与前端门禁、迁移往返、固定 RAG 评测、53 项脚本契约和阶段 2–7 smoke，不联网、不访问真实设备、不产生费用。

## 文档导航

- [产品需求](docs/requirements/product-requirements.md)
- [系统设计](docs/architecture/system-design.md)
- [开发路线](docs/plans/development-roadmap.md)
- [Windows 本地开发](docs/operations/local-development.md)
- [安全标准](docs/standards/security-standards.md)

任何 API Key、密码、令牌、真实告警或客户数据都不得写入代码、测试夹具、日志或版本库。

## Docker Compose 部署

安装 Docker Engine 与 Compose v2 后，可运行：

```powershell
docker compose up --build
```

浏览器访问 `http://127.0.0.1:8080`。Compose 会先执行 Alembic 迁移，再启动仅在内部网络暴露的后端和非 root Nginx 前端；SQLite 数据保存在命名卷中。停止服务使用 `docker compose down`，该命令默认保留数据卷。

本仓库仍支持不依赖 Docker 的 Windows 本地开发。本次交付环境没有 Docker CLI，因此只验证了 Dockerfile、Nginx 和 Compose 的静态安全合同，未验证镜像构建或容器运行：`DOCKER_RUNTIME_TESTED=False`。
