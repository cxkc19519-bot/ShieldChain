# 真实防火墙处置连接器

ShieldChain 当前提供一条受控的实验室真实处置链路：响应规划智能体提出 `block_ip`，确定性策略要求人工审批，可信工具网关调用独立执行器，执行器把地址加入服务器 `nftables` 的 `inet shieldchain` 表，随后网关重新查询并验证结果。

## 当前能力边界

- 只有 `query_firewall_state` 和 `block_ip` 会进入真实连接器。
- 终端隔离与账号禁用仍使用非真实适配器，不能表述为已接入 EDR 或目录服务。
- 默认只允许三个 RFC 5737 文档测试网段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`。
- 封禁规则必须带 60 秒至 24 小时的 TTL，到期由 nftables 自动移除。
- 执行器只接受固定 JSON 字段，不接受命令、脚本或任意 nftables 表达式。
- 执行器使用独立令牌，容器只增加 `NET_ADMIN`，并丢弃其他 Linux capabilities。
- 生产环境的页面写操作默认关闭；实验室启用需要显式设置 `RESPONSE_OPERATOR_CONTROLS_ENABLED=true`。这不是生产级 RBAC 的替代品。

## 配置

在服务器 `.env` 中配置：

```dotenv
RESPONSE_CONNECTOR_MODE=nftables_http
RESPONSE_FIREWALL_EXECUTOR_URL=http+unix:///run/shieldchain-executor/executor.sock
RESPONSE_FIREWALL_EXECUTOR_TOKEN=<至少 24 字符的随机令牌>
RESPONSE_FIREWALL_ALLOWED_CIDRS=192.0.2.0/24,198.51.100.0/24,203.0.113.0/24
RESPONSE_OPERATOR_CONTROLS_ENABLED=true
```

使用服务器编排启动：

```bash
docker compose -f compose.yaml -f compose.server.yaml up -d --build
```

## 验收顺序

1. 执行器健康检查确认共享 Unix 套接字 `/run/shieldchain-executor/executor.sock` 可以连接；执行器不监听宿主机 TCP 端口。
2. 未携带令牌的写请求返回 401。
3. 封禁非允许网段返回 400。
4. 封禁 `203.0.113.25` 后，`nft get element inet shieldchain blocked_ipv4 { 203.0.113.25 }` 成功。
5. 查询接口返回 `firewall_status=blocked`。
6. TTL 到期后查询返回 `firewall_status=not_blocked`。
7. 从处置中心接受计划后，`block_ip` 仍需独立人工审批；审批后执行尝试和验证结果必须出现在可信轨迹中。

## 扩大到真实地址前必须完成

默认测试网段不足以处置真实公网攻击源。扩大允许范围前，必须先加入服务器地址、SSH 管理来源、学校网关、DNS、VPN、容器网段和业务依赖白名单，并完成误封、自动解封、审计、备份恢复和失联演练。真实生产环境还需要管理员身份认证、RBAC、双人审批、密钥托管和变更工单。
