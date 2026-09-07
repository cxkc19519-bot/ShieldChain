# 实验室真实响应连接器

ShieldChain 当前提供三类受控的实验室真实链路：宿主机 nftables 执行器负责 IP 查询、封禁和解封；端点链路负责查询 Wazuh 白名单 Agent，并在演示 Agent 自己的网络命名空间内执行隔离和恢复；文件链路负责在独立实验数据卷中查询、隔离和恢复允许名单文件。模型只能从服务端候选中选择工具，目标仍由案件证据解析，不能自行填写 IP、Agent ID、路径、命令或连接地址。

## 当前能力边界

- `query_firewall_state`、`block_ip` 和 `unblock_ip` 已连接真实 nftables 执行器。
- `query_endpoint_state`、`isolate_endpoint` 和 `restore_endpoint` 已连接演示 Agent `002`。查询同时读取 Wazuh Agent 元数据和独立 nftables 隔离状态。
- `query_file_state`、`quarantine_file` 和 `restore_file` 已连接独立文件实验卷。告警只携带不透明 `file_id`；执行器把它映射为固定文件名，不接受路径。
- 案件首次响应规划可把查询和隔离作为候选交给模型自主选择；恢复不会被首次规划自动推荐，只用于后续人工确认的回滚计划。
- `unblock_ip` 已进入可信工具注册表和真实适配器，但当前案件首次响应规划不会自动推荐解封；它用于后续人工确认的回滚/误报恢复计划。
- 端点隔离只作用于容器化演示 Agent 的出站流量，不等同于 Windows EDR 主机隔离；账号禁用与账号恢复仍未接入真实系统。
- 文件隔离只作用于 `shieldchain-file-response-lab` 命名卷中的允许名单文件，不是宿主机任意文件操作，也不是生产 EDR 文件隔离。
- 默认只允许三个 RFC 5737 文档测试网段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`。
- 封禁规则必须带 60 秒至 24 小时的 TTL，到期由 nftables 自动移除。
- 执行器只接受固定 JSON 字段，不接受命令、脚本或任意 nftables 表达式。
- 执行器使用独立令牌，容器只增加 `NET_ADMIN`，并丢弃其他 Linux capabilities。
- Wazuh 执行器是另一个非 root、`cap_drop: ALL` 的容器，只通过独立 Unix Socket 对后端提供固定查询接口。它不接收任意 URL、查询表达式或命令。
- 端点执行器共享 `shieldchain-demo-agent-wazuh.agent-1` 的网络命名空间，只拥有 `NET_ADMIN`；它没有宿主机网络命名空间，也不监听宿主机端口。隔离规则放行回环、已有连接以及 TCP 1514/1515 管理通道。
- 端点隔离必须携带 60 秒至 24 小时 TTL，nftables 到期自动删除状态；恢复动作同样属于高风险写操作，必须独立人工审批。
- 文件执行器拒绝路径、符号链接、超过 10 MiB 的文件、缺失状态和双文件状态；隔离采用同卷原子重命名、移除写/执行权限并在前后计算 SHA-256。
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
RESPONSE_ALLOWED_FILE_IDS=demo-suspicious-marker
WAZUH_AGENT_CONTAINER=shieldchain-demo-agent-wazuh.agent-1
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

1. 三个执行器健康检查确认 Unix 套接字可连接；它们都不监听宿主机 TCP 端口。
2. 未携带令牌的写请求返回 401。
3. 封禁非允许网段返回 400。
4. 封禁 `203.0.113.25` 后，`nft get element inet shieldchain blocked_ipv4 { 203.0.113.25 }` 成功。
5. 查询接口返回 `firewall_status=blocked`。
6. TTL 到期后查询返回 `firewall_status=not_blocked`。
7. 从处置中心接受计划后，`block_ip` 仍需独立人工审批；审批后执行尝试和验证结果必须出现在可信轨迹中。
8. 对测试地址执行 `unblock_ip` 后，独立查询必须返回 `firewall_status=not_blocked`。
9. Wazuh 查询 Agent `002` 返回真实名称、版本、连接状态以及 `isolation_status=connected`；查询 Agent `001` 被执行器白名单拒绝。
10. 对 Agent `002` 发起 60 秒隔离后，独立查询返回 `isolation_status=isolated`，Wazuh Agent 仍保持管理连接。
11. 人工批准 `restore_endpoint` 后，独立查询返回 `isolation_status=connected`；不手动恢复时，TTL 到期也必须自动回到 connected。
12. 文件告警 evidence 中的 `file_id` 必须同时位于服务端和执行器允许名单；模型不能把路径放进计划。
13. 接受文件计划后，只读查询可以自动执行，`quarantine_file` 必须等待独立人工审批；隔离后查询返回 `file_status=quarantined` 且 SHA-256 不变。
14. 恢复文件后查询返回 `file_status=present`，SHA-256 与隔离前一致；路径穿越和非允许名单 ID 必须拒绝。

完整 Wazuh 案件验收使用 `scripts/verify_wazuh_response_e2e.py`。脚本要求显式 `--execute`，每次生成唯一告警与规则 ID，目标固定为 `203.0.113.25`，并通过执行器 Unix socket 在 TTL 后独立确认规则已经自动清理。端点执行器底层验收使用 `scripts/verify_endpoint_response_e2e.py --execute --verify-ttl`；完整控制面验收使用 `scripts/verify_wazuh_endpoint_control_plane_e2e.py --execute --ttl 60`。文件链路验收使用 `scripts/verify_wazuh_file_response_e2e.py --execute`。详细命令及阶段输出见 [Wazuh 只读告警接入](wazuh-read-only-ingestion.md)。2026-09-05 的案件验收见 [Wazuh 案件真实处置闭环验收](../reports/wazuh-case-response-e2e-2026-09-05.md)，端点验收见 [真实连接器第二阶段](../reports/real-connectors-stage-2-2026-09-06.md)，文件验收见 [真实连接器第三阶段](../reports/real-connectors-stage-3-file-quarantine-2026-09-06.md)。

## 扩大到真实地址前必须完成

默认测试网段不足以处置真实公网攻击源。扩大允许范围前，必须先加入服务器地址、SSH 管理来源、学校网关、DNS、VPN、容器网段和业务依赖白名单，并完成误封、自动解封、审计、备份恢复和失联演练。当前端点隔离是容器实验能力；真实 Windows/Linux 终端仍需经过签名的 Active Response/EDR 脚本、按终端动态保留管理地址、隔离后新遥测验证、离线恢复和失联兜底。生产环境还需要管理员身份认证、RBAC、双人审批、密钥托管和变更工单。
