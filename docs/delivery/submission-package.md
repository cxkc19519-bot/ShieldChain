# ShieldChain 比赛提交包

> 文档状态：当前参考（更新于 2026-08-08）。提交内容以当前 Git 跟踪文件和本页验收边界为准。

## 内容范围

- FastAPI 后端、数据库迁移、锁定依赖和自动化测试；
- React/Vite 前端、锁文件、构建配置和测试；
- 七个专业角色、ReAct 编排、可信工具网关与只读安全运营 MCP 工具；
- Wazuh/OpenSearch 接入、持久化 RAG、智能助手和安全运营报告；
- 本地 vLLM/Qwen 部署配置、服务器运维脚本与相关文档；
- 需求、架构、运维、交付、历史验收快照和开发决策记录。

Remotion 工程、比赛 MP4、旧视频测试和固定钓鱼模拟入口已经退出当前交付范围。

## 可复现交付

仓库仍保留确定性打包脚本。打包器以 `git ls-files` 为输入，排除 `.env`、虚拟环境、`node_modules`、运行数据库、缓存和临时渲染目录。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\run-phase8-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\build-phase8-package.ps1
Get-FileHash -Algorithm SHA256 delivery\shieldchain-submission.zip
```

完整工程门禁：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify.ps1
```

## 当前验收边界

- 后端新增真实运营、ReAct、MCP 与报告链路已有针对性自动化测试；
- 前端类型检查、核心组件测试和生产构建可在本地执行；
- Wazuh 与 OpenSearch 已在学校服务器 Docker 环境实际部署和验证，不再属于“未验证 Docker”状态；
- 本地 vLLM Compose 配置和镜像链路已经准备，Qwen 模型权重下载与常驻服务启动取决于代理连通性和共享 RTX 4090 的可用时段；
- 外部 DeepSeek 与本地 OpenAI 兼容模型均属于可配置模型后端；
- 真实告警读取为只读路径，真实防火墙封禁、终端隔离等高风险设备写操作仍未纳入当前自动执行范围；
- 历史报告中的测试数量和 `*_TESTED` 标志只代表生成报告时的版本，不应覆盖本节状态。

## 提交前检查

1. 运行后端和前端测试；
2. 校验 Compose 配置；
3. 确认 `.env`、密钥、真实告警样本和运行数据库未被提交；
4. 检查 `git status`，只纳入本次授权范围；
5. 重新生成 ZIP 和校验和时，确认其中不包含已经退役的视频资产。