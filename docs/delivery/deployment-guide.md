# ShieldChain 部署手册

## Compose 演示部署

前置条件是 Docker Engine 与 Compose v2。仓库根目录运行：

```powershell
docker compose up --build
```

访问 `http://127.0.0.1:8080`。`migrate` 完成 `alembic upgrade head` 后，后端等待 readiness，前端 Nginx 最后启动。后端不向宿主机发布端口。

## 健康检查

```powershell
Invoke-WebRequest http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/api/v1/health/live
Invoke-RestMethod http://127.0.0.1:8080/api/v1/health/ready
Invoke-RestMethod http://127.0.0.1:8080/api/v1/health/version
```

Liveness 不检查依赖；readiness 要求数据库可用、Alembic 精确位于 `20260724_01` 且应用仍接受请求；version 只公开服务、包版本和期望 schema。

## 停止与数据

`docker compose down` 停止容器并保留 project-scoped SQLite 卷。只有明确决定删除演示数据时才执行 `docker compose down -v`。先导出所需报告和审计结果，不要删除未知 Compose project 或卷。

## 安全配置

容器以固定非 root UID 运行，根文件系统只读、capabilities 全部删除并启用 `no-new-privileges`。真实 API key 和设备凭据必须由平台密钥服务在运行时注入，不能进入 Dockerfile、Compose、`.env.example`、镜像层或日志。生产域名必须替换 Host/Origin 白名单；不得使用通配符。

## 验收与回滚

部署前运行 `scripts/verify.ps1` 和 `tests/scripts/run-phase8-container-smoke.ps1`。数据库变更必须先验证备份和 downgrade；应用回滚不能盲目跨越不兼容 schema。当前迁移可逆，但比赛拓扑没有自动备份、滚动发布或高可用控制面。

## 限制

该 Compose 面向单机演示。SQLite 不支持多副本写入，Nginx 仅绑定回环地址，没有 TLS 终止、外部身份提供方、镜像签名或集群网络策略。本机尚未运行 Docker：`DOCKER_RUNTIME_TESTED=False`。生产部署必须在授权环境补齐容器 smoke、漏洞扫描、签名、备份恢复和真实适配器验收。
