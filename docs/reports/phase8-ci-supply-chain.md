# Phase 8 CI 与供应链合同报告

> 文档状态：历史验收快照。记录当时版本的测试结果与限制，不等同于当前版本状态。

## 结论

Task 6 已交付精确 Python 锁文件、npm lockfile integrity 合同、完整 SHA 固定的最小权限 CI，以及 Docker 可用时自动升级为真实运行态验收的 Compose smoke。本机没有 Docker CLI，GitHub Actions 也未远端执行，因此只确认本地静态与依赖一致性门禁。

- `DOCKER_RUNTIME_TESTED=False`
- `CI_RUNTIME_TESTED=False`

## 本地已验证

- 运行时与测试 Python 包使用 `==` 固定，不允许 URL 或 Git 依赖源；Linux uvloop 使用平台 marker。
- npm v3 lockfile 中 registry 包具有 SHA-512 integrity，且不包含 Git 或 token URL。
- GitHub Actions 只具备 `contents: read`，checkout 禁用凭据持久化，action 引用均为 40 位 commit SHA。
- Compose 卷使用随机 project 命名空间，smoke cleanup 仅删除自有 project 资源。
- Docker 缺失时脚本明确输出未测状态，静态合同仍失败关闭。
- `pip check` 报告没有破损依赖。

## CI 门禁

Windows job 安装锁定依赖后运行完整 `verify.ps1` 与静态容器合同。Linux job安装测试依赖并运行真实 Compose smoke；该 smoke 验证前端健康、后端 readiness/version、非 root UID 和只读根文件系统，最后删除自有容器、网络和卷。

CI 不启用真实 DeepSeek、Embedding、Milvus、Reranker、模型规划或安全设备路径。依赖安装和镜像拉取需要 registry 网络，但应用验证路径不访问这些真实服务。

## 未验证边界

- 当前主机未构建镜像或启动 Compose。
- 工作流尚未推送到 GitHub，因此 runner、缓存和 Linux Docker job 尚未产生远端证据。
- 基础镜像标签尚未由本机 registry 拉取确认。
- 依赖一致性检查不是基于实时漏洞情报库的 CVE 扫描。

容器与 CI 运行通过只能由具备 Docker Engine 且实际执行工作流的环境补充，不能由本报告推断。
