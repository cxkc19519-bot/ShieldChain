# 实验室真实响应连接器

ShieldChain 当前提供两类受控的实验室真实链路：nftables 防火墙执行器负责 IP 查询、封禁和解封；Wazuh 只读执行器负责查询白名单 Agent 状态。模型只能从服务端候选中选择工具，目标仍由案件证据解析，不能自行填写 IP、Agent ID、命令或连接地址。

## 当前能力边界

- `query_firewall_state`、`block_ip` 和 `unblock_ip` 已连接真实 nftables 执行器。
- `query_endpoint_state` 已连接真实 Wazuh API，只允许查询 Agent `002`；案件规划可将它作为只读候选交给模型自主选择。
- `unblock_ip` 已进入可信工具注册表和真实适配器，但当前案件首次响应规划不会自动推荐解封；它用于后续人工确认的回滚/误报恢复计划。
- `isolate_endpoint`、终端恢复、账号禁用与账号恢复仍未接入真实系统，不能表述为已经具备 EDR 隔离或目录服务处置。
- 默认只允许三个 RFC 5737 文档测试网段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`。
- 封禁规则必须带 60 秒至 24 小时的 TTL，到期由 nftables 自动移除。
- 执行器只接受固定 JSON 字段，不接受命令、脚本或任意 nftables 表达式。
- 执行器使用独立令牌，容器只增加 `NET_ADMIN`，并丢弃其他 Linux capabilities。
- Wazuh 执行器是另一个非 root、`cap_drop: ALL` 的容器，只通过独立 Unix Socket 对后端提供固定查询接口。它不接收任意 URL、查询表达式或命令。
- Wazuh API 使用专用 `agents_readonly` 身份；执行器再以 `RESPONSE_WAZUH_ALLOWED_AGENT_IDS` 做第二层 Agent 白名单。凭据只保存在服务器 `secrets/wazuh-readonly.env`（目录 0700、文件 0600），不进入主后端、Git 或日志。
- 生产环境的页面写操作默认关闭；实验室启用需要显式设置 `RESPONSE_OPERATOR_CONTROLS_ENABLED=true`。这不是生产级 RBAC 的替代品。

## 配置

在服务器 `.env` 中配置：

```dotenv
RESPONSE_CONNECTOR_MODE=nftables_http
RESPONSE_FIREWALL_EXECUTOR_URL=http+unix:///run/shieldchain-executor/executor.sock
RESPONSE_FIREWALL_EXECUTOR_TOKEN=<至少 24 字符的随机令牌>
RESPONSE_FIREWALL_ALLOWED_CIDRS=192.0.2.0/24,198.51.100.0/24,203.0.113.0/24
RESPONSE_WAZUH_ALLOWED_AGENT_IDS=002
RESPONSE_OPERATOR_CONTROLS_ENABLED=true
```

使用服务器编排启动：

```bash
docker compose \
  -f compose.yaml \
  -f compose.local-llm.yaml \
  -f compose.server.yaml \
  up -d --build
```

## 验收顺序

1. 两个执行器健康检查确认 Unix 套接字可连接；它们都不监听宿主机 TCP 端口。
2. 未携带令牌的写请求返回 401。
3. 封禁非允许网段返回 400。
4. 封禁 `203.0.113.25` 后，`nft get element inet shieldchain blocked_ipv4 { 203.0.113.25 }` 成功。
5. 查询接口返回 `firewall_status=blocked`。
6. TTL 到期后查询返回 `firewall_status=not_blocked`。
7. 从处置中心接受计划后，`block_ip` 仍需独立人工审批；审批后执行尝试和验证结果必须出现在可信轨迹中。
8. 对测试地址执行 `unblock_ip` 后，独立查询必须返回 `firewall_status=not_blocked`。
9. Wazuh 查询 Agent `002` 返回真实名称、版本和连接状态；查询 Agent `001` 被执行器白名单拒绝。

完整 Wazuh 案件验收使用 `scripts/verify_wazuh_response_e2e.py`。脚本要求显式 `--execute`，每次生成唯一告警与规则 ID，目标固定为 `203.0.113.25`，并通过执行器 Unix socket 在 TTL 后独立确认规则已经自动清理。详细命令及阶段输出见 [Wazuh 只读告警接入](wazuh-read-only-ingestion.md)。2026-09-05 的服务器验收记录见 [Wazuh 案件真实处置闭环验收](../reports/wazuh-case-response-e2e-2026-09-05.md)。

## 扩大到真实地址前必须完成

默认测试网段不足以处置真实公网攻击源。扩大允许范围前，必须先加入服务器地址、SSH 管理来源、学校网关、DNS、VPN、容器网段和业务依赖白名单，并完成误封、自动解封、审计、备份恢复和失联演练。真实终端隔离还需要受控 Active Response 脚本、保留管理通道、TTL 自动恢复、隔离后新遥测验证和失联兜底；当前演示 Agent 没有 `NET_ADMIN`，因此本阶段没有把模拟隔离包装成真实能力。生产环境还需要管理员身份认证、RBAC、双人审批、密钥托管和变更工单。
