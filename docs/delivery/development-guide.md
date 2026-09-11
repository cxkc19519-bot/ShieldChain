# ShieldChain 开发说明

> 文档状态：历史开发交付指南。部分阶段名称和命令用于版本追溯；当前开发与部署方式请优先阅读 `docs/README.md`、`operations/local-development.md` 和 `delivery/deployment-guide.md`。

## 环境

支持 Python `>=3.12,<3.15`、Node.js 24/LTS 和 Windows PowerShell。复制 `.env.example` 为本地 `.env`，不得提交真实密钥。完整安装：

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".\backend[test]"
npm ci --prefix frontend
Copy-Item .env.example .env
```

## 日常命令

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

后端默认 `127.0.0.1:8000`，前端默认 `127.0.0.1:5173`。`verify.ps1` 按 Ruff、完整后端、前端 lint/type/test/build、前端依赖审计、Alembic `upgrade → downgrade -1 → upgrade`、RAG 评测、脚本合同和 Task 14 smoke 顺序失败即停。Python 可来自根目录 `.venv`、`backend/.venv` 或 CI PATH。

## 数据库修改

模型位于各领域 persistence 模块，迁移位于 `backend/migrations/versions`。任何 schema 修改必须包含 upgrade/downgrade、fresh database 测试和查询计划检查（若涉及热路径）。本地迁移：

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m alembic upgrade head
```

不要删除未知数据库，不要对仓库根目录运行递归清理。smoke 使用带 GUID 的系统临时目录并只清理自有资源。

## 开发流程

先写合同或失败测试，再实现最小变更；运行受影响测试和完整门禁；同步设计、运维与开发日志；每个 Task 独立提交。保持 port/adapter 边界，避免在路由中实现领域规则。对公开模型采用白名单，不把内部 ORM 或适配器对象直接序列化。

## 依赖

Python CI 使用 `backend/requirements.lock`，生产镜像使用 `backend/requirements-runtime.lock`；前端必须使用 `npm ci` 和 `frontend/package-lock.json`。升级依赖时重新生成锁、运行 `pip check`/`npm ls`、完整测试和容器合同，并记录未执行的在线漏洞扫描边界。

## 真实集成

DeepSeek、Embedding、Milvus、Reranker、模型自主规划和安全设备默认不得调用。只有获得授权、预算和安全密钥注入后，才能使用单独 live profile；离线测试结果不能写成真实集成通过。
