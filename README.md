# 盾链智御（ShieldChain）

盾链智御是一个面向网络安全运营的智能体研究项目。当前阶段 2 提供 Windows 本地可运行的 FastAPI 后端、React 调查页面和基于 SQLite 的确定性钓鱼事件闭环。它是仿真演示，不是真实防护设备：不会调用真实防火墙、EDR、SIEM、DeepSeek 或其他外部服务。RAG、多智能体和真实设备集成等后续能力尚未实现。

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
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

前端地址为 `http://127.0.0.1:5173`，后端地址为 `http://127.0.0.1:8000`。独立 smoke 会迁移临时 SQLite、启动真实后端和 Vite 严格端口代理，并仅通过 5173 完成 reset/start/poll/audit 闭环；它会清理自己创建的进程和临时文件。`verify.ps1` 在既有质量门禁全部成功后运行同一 smoke。所有默认门禁都会清除继承的实时测试开关，不产生付费 DeepSeek 调用。

## 文档导航

- [产品需求](docs/requirements/product-requirements.md)
- [系统设计](docs/architecture/system-design.md)
- [开发路线](docs/plans/development-roadmap.md)
- [Windows 本地开发](docs/operations/local-development.md)
- [安全标准](docs/standards/security-standards.md)

任何 API Key、密码、令牌、真实告警或客户数据都不得写入代码、测试夹具、日志或版本库。
