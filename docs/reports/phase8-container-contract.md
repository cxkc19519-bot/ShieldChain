# Phase 8 容器部署合同报告

## 结论

Task 5 已交付后端与前端多阶段 Dockerfile、非 root Nginx 配置、Compose 迁移与健康依赖拓扑，以及静态安全合同测试。当前开发主机没有 Docker CLI，因此本报告只证明源文件合同通过，不证明镜像已构建或容器已运行。

`DOCKER_RUNTIME_TESTED=False`

## 已静态验证

- 后端镜像分离构建和运行阶段，最终阶段使用固定 UID 10001，默认启动 Uvicorn factory，并提供 liveness 健康检查。
- 前端镜像在 Node 构建阶段生成静态资源，最终阶段使用非 root Nginx UID 101 和 8080 端口。
- Nginx 提供 `/healthz`、SPA fallback、安全响应头和 `/api/` 反向代理，不把上游身份头直接透传。
- Compose 先迁移、后启动后端，再按 readiness 启动前端；后端不发布宿主机端口。
- 服务启用只读根文件系统、删除 capabilities、`no-new-privileges`、明确 `tmpfs` 和 SQLite 命名卷。
- Compose 和 Dockerfile 不包含 API key、密码或密钥值。
- `.dockerignore` 排除本地配置、依赖、缓存、测试数据、数据库、日志和交付产物。

静态测试命令：

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests\integration\test_container_contract.py -q
```

结果：`5 passed`。

## 未验证边界

以下项目尚未执行：

- 从 registry 拉取所声明的基础镜像标签；
- 构建后端和前端镜像；
- 执行 `docker compose up`；
- 在容器命名空间中确认实际 UID、只读根文件系统和 capability 集合；
- 通过 Nginx 访问 liveness、readiness、version 和前端 SPA；
- 容器关闭、重启与 SQLite 卷恢复。

这些检查将在提供 Docker Engine 的授权环境中由 Task 6 smoke 执行。本报告不将静态源文件检查等同于运行态验收。
