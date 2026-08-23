# 部署手册

> 文档状态：当前参考（更新于 2026-08-23）。Docker 与 Wazuh 已在学校服务器环境实际使用；本地 30B 模型仍受权重下载和共享 GPU 可用性约束。MCP OAuth/JWKS 已通过本地协议与配置测试，真实身份平台、TLS 和 Nginx 容器链路尚待授权环境验收。

## 基础 Compose

```bash
docker compose up -d --build
```

前端绑定 `127.0.0.1:8080`，后端仅在 Compose 内部网络提供服务。数据库、知识库和助手数据位于持久化卷；`docker compose down` 默认保留数据。

## 服务器覆盖

```bash
docker compose -f compose.yaml -f compose.server.yaml up -d --build
```

服务器工作目录限定为 `/home/user/jhk/shieldchain`。`.env` 位于服务器私有目录，不进入镜像和版本库。

从本地浏览器访问服务器前端时使用 SSH 本地端口转发，不需要在服务器安装桌面环境：

```powershell
ssh -i C:\Users\a\.ssh\shieldchain_lab_ed25519 -p 1100 `
  -L 18080:127.0.0.1:8080 jhk@121.48.164.89
```

然后访问 `http://127.0.0.1:18080`。

## MCP 生产入口

MCP 默认关闭。ShieldChain 只作为 OAuth Resource Server，不提供登录页、授权服务器、动态客户端注册或 Token 签发。启用前必须准备：

- 可通过 HTTPS 访问的外部 OAuth/OIDC issuer 和 JWKS；
- 对外稳定的 MCP resource URI，必须精确到 `/mcp`；
- Authorization Server 签发给该 audience/resource 的短生命周期 JWT；
- 经过管理员复核的 subject → ShieldChain principal UUID 映射；
- 位于当前 Nginx 之前的 TLS 终止层，以及与公网域名一致的 `HTTP_ALLOWED_HOSTS`。

私有 `.env` 示例：

```dotenv
ENVIRONMENT=production
MCP_SERVER_ENABLED=true
MCP_AUTH_MODE=oauth
MCP_AUTH_ISSUER=https://identity.example.edu
MCP_AUTH_RESOURCE=https://shieldchain.example.edu/mcp
MCP_AUTH_JWKS_URL=https://identity.example.edu/.well-known/jwks.json
MCP_AUTH_AUDIENCE=shieldchain-mcp
MCP_AUTH_ALGORITHM=RS256
MCP_AUTH_MAX_TOKEN_LIFETIME_SECONDS=900
MCP_AUTH_SUBJECT_PRINCIPALS={"security-operator":"00000000-0000-4000-8000-000000000010"}
HTTP_ALLOWED_HOSTS=["shieldchain.example.edu","backend","localhost","127.0.0.1"]
HTTP_ALLOWED_ORIGINS=["https://shieldchain.example.edu"]
```

subject 映射是服务器权限配置，不能从 Token 的 tenant/principal 同名 claim 自动生成。删除、替换或新增映射后必须滚动重启后端。不得把 Access Token、client secret、私钥或完整 JWT 写入 `.env.example`、Compose、Git、日志或报告。

基础 scope 为 `shieldchain:mcp`。调用工具还必须包含对应读取 scope：

| 工具 | scope |
| --- | --- |
| `security.events.list` | `shieldchain:events:read` |
| `security.alerts.list` | `shieldchain:alerts:read` |
| `security.vulnerabilities.list` | `shieldchain:vulnerabilities:read` |
| `security.weak_passwords.list` | `shieldchain:auth-risk:read` |

配置与启动：

```bash
docker compose config --quiet
docker compose run --rm migrate
docker compose up -d --build backend frontend
docker compose ps
```

验证 Protected Resource Metadata 和未认证 challenge：

```bash
curl --fail --silent --show-error \
  https://shieldchain.example.edu/.well-known/oauth-protected-resource/mcp

curl --include --request POST \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json, text/event-stream' \
  --header 'MCP-Protocol-Version: 2026-07-28' \
  --header 'Mcp-Method: server/discover' \
  --data '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"deployment-check","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}' \
  https://shieldchain.example.edu/mcp
```

第二条命令必须返回 401，`WWW-Authenticate` 必须包含 HTTPS `resource_metadata`。真实 Token 验证应使用短期测试主体和最小 scope；把 Token 放在进程环境或受控 Secret 注入中，禁止写入 shell 历史。测试结束后检查 `/api/v1/mcp/runs/{run_id}/calls` 和服务日志，确认只有公开审计字段且没有 Authorization 内容。

Nginx 对 `/mcp` 使用每 IP 10 请求/秒、burst 20、256 KiB 请求体上限，关闭代理请求/响应缓冲和缓存，并清空不可信 `X-Forwarded-*`。当前 Compose 前端只绑定 `127.0.0.1:8080`，因此生产域名必须由更外层受控反向代理提供 TLS；不得直接把 8080 暴露到公网。

当前仅支持签名 JWT，不支持 opaque token introspection 或即时单 Token 撤销。Authorization Server 必须把 Token 生命周期限制在配置上限内；紧急撤销使用 issuer/JWKS 密钥停用、subject 映射删除和后端重启。JWKS 正常轮换由 SDK 依赖的缓存客户端重新获取，旧密钥停用前需保留合理重叠窗口。

关闭与回滚：

```bash
MCP_SERVER_ENABLED=false docker compose up -d backend frontend
curl --include https://shieldchain.example.edu/mcp
```

关闭后 `/mcp` 不应再由后端提供。保留数据库中的 `agent_tool_calls` 审计；已有审计行时 Alembic 会拒绝降级删除审计表。若必须回滚代码，先备份数据库并按留存要求迁移审计记录，不得关闭外键或直接删除表绕过保护。

## 外部 MCP 目录发现

外部 MCP 默认未配置且不会联网。当前实现只发现目录并保存快照，不执行远程 `tools/call`；远程 Provider、结果裁剪、调用预算和熔断属于后续 Task 8。

从示例复制实际配置。实际文件已被 `.gitignore` 排除：

```bash
cp config/mcp/servers.example.yaml config/mcp/servers.yaml
chmod 600 config/mcp/servers.yaml
```

编辑时必须保持以下边界：

- peer 和工具由管理员逐项声明，模型、Skill、RAG 文档和普通 HTTP 请求不能添加 endpoint；
- 只允许 HTTPS、443 和固定 `/mcp` 路径，不允许 userinfo、query、fragment、stdio 或重定向；
- `public_https` 的全部 DNS 结果必须为公开单播地址；内网使用 `internal_https` 并设置固定 `allowed_cidrs`；
- 远端 annotation 不是权限依据，`classification: read_only` 和 `allowed_roles` 以本地配置为准；
- `schema_revision` 是管理员审批标签。远端 Schema 变化时先保持旧值启动验证；看到 `mcp_schema_changed` 后复核新结构，确认安全才提升 revision；
- `token_env` 只写环境变量名称，不写 Token。每个 peer 使用独立 Token，不得复用 ShieldChain 入站用户 Token；
- TLS 校验不能关闭。内部 CA 使用容器内绝对路径 `tls_ca_bundle`，并以只读 bind mount 注入。

示例内网配置片段：

```yaml
network_policy: internal_https
allowed_cidrs: [10.20.0.0/16]
tls_ca_bundle: /run/shieldchain/mcp/internal-ca.pem
```

Compose 需要显式挂载实际配置并传入该 peer 的独立 Secret。建议放在不提交的 `compose.override.yaml`：

```yaml
services:
  backend:
    volumes:
      - ./config/mcp/servers.yaml:/run/shieldchain/mcp/servers.yaml:ro
    environment:
      MCP_REMOTE_CONFIG_PATH: /run/shieldchain/mcp/servers.yaml
      APPROVED_SECURITY_PLATFORM_MCP_TOKEN: ${APPROVED_SECURITY_PLATFORM_MCP_TOKEN:?required}
```

启动与更新：

```bash
export APPROVED_SECURITY_PLATFORM_MCP_TOKEN='从受控 Secret 系统注入，不要写入 shell 历史'
docker compose config --quiet
docker compose run --rm migrate
docker compose up -d --build backend
docker compose logs --since=10m backend
```

启动时官方 MCP Client 使用 `auto` 协商，优先 `2026-07-28` 并可兼容 `2025-11-25`。连接固定到预解析且通过策略的 IP，同时保留原 Host/TLS SNI 并核对实际 socket peer；发现结束后 DNS 答案改变会拒绝本次目录。重定向、环境代理和 TLS 关闭均不允许。

发现成功会写入 `mcp_peer_snapshots` 与 `mcp_tool_snapshots`。快照不保存 Bearer Token、Authorization Header 或异常详情。刷新失败会保存稳定原因码；最近一次成功目录可供管理员查看，但过期后不能用于新调用。目录 revision 为随机 UUID，Schema 变化通过结构比较和管理员 `schema_revision` 审批，不额外计算文件或 Schema 哈希。

关闭、轮换与回滚：

1. 将 peer 改为 `enabled: false` 或清空 `MCP_REMOTE_CONFIG_PATH`，滚动重启后端；
2. Token 轮换时只更新 Secret 注入并重启，不修改或提交 YAML；
3. 保留快照用于审计。`20260823_03` 在存在快照时拒绝降级删表；确需回滚必须先备份并按留存策略迁移记录；
4. 当前没有远程工具调用，因此关闭发现不会产生远端动作，也不需要伪造撤销结果。

## 本地模型覆盖

```bash
LOCAL_LLM_CACHE_DIR=/home/user/jhk/huggingface \
docker compose -f compose.yaml -f compose.local-llm.yaml up -d
```

覆盖配置启动 vLLM `Qwen/Qwen3-30B-A3B-Instruct-2507-FP8`，模型服务绑定服务器回环地址 `127.0.0.1:8001`，后端容器通过 `http://local-llm:8000/v1` 访问。

当前参数面向两张 RTX 4090：流水线并行 2、最大上下文 16384、最大并发序列 4。启动前必须确认：

- 权重下载完整；
- NVIDIA Container Toolkit 可用；
- 两张 GPU 有足够空闲显存；
- 已与共享服务器其他用户协调资源。

不得终止或修改其他用户 GPU 进程。如果流水线并行不受模型实现支持，再在独立验证后评估张量并行和禁用自定义 all-reduce 的备用方案。

## Wazuh

Wazuh Manager、Indexer/OpenSearch 和 Dashboard 运行在服务器 Docker 环境。Windows Wazuh Agent 或离线数据集向 Manager 提供遥测；`scripts/wazuh/custom-shieldchain` 将满足条件的告警只读转发到 ShieldChain。

## 代理

校园服务器无法直接访问部分镜像仓库时，可通过 SSH 反向隧道使用本机 Clash 代理。代理只用于镜像和模型下载，不应成为生产请求链路的一部分。完成下载后关闭临时隧道，并确认 Docker 代理配置不会暴露到外部网络。

## 上线前检查

- 更换所有默认密码与 Token；
- 限制监听地址并配置 TLS、身份认证和最小权限；
- 备份数据库、知识库、助手会话和 Wazuh 索引；
- 验证恢复、磁盘容量、日志轮转和告警留存；
- 对镜像执行漏洞扫描并固定摘要；
- 对真实处置工具单独进行审批、幂等和回滚验收。
