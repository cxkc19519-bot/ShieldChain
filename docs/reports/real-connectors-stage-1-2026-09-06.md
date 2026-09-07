# 真实连接器扩展第一阶段验收（2026-09-06）

## 本阶段结果

- 新增 `unblock_ip@1` 可信工具：只接受白名单 IPv4 和枚举原因，风险为 high，必须独立人工审批，执行后由 `query_firewall_state` 验证。
- 防火墙执行器已有的固定解封接口现已接入工具注册表、仿真兼容层、真实适配器和 ReAct 公共动作白名单。
- 新增独立 Wazuh 只读执行器与 `WazuhHttpAdapter`，主后端只持有内部 Socket 令牌，不持有 Wazuh API 密码。
- Wazuh 中创建专用只读 API 身份，凭据仅保存在服务器 mode-0600 secret 文件；执行器只允许 Agent `002`。
- Wazuh 案件证据现保留 `agent_id`，响应规划智能体可在服务端候选中自主选择 `query_endpoint_state`，模型不能提供或修改 Agent ID。

## 实际验收

- 连接器、响应规划与运营报告定向测试：30 项通过。
- 完整后端回归：1238 项通过、33 项跳过，无失败。
- 后端与 Wazuh 执行器镜像构建成功，后端和执行器健康。
- Wazuh Agent `002` 返回 `shieldchain-server-demo`、`Wazuh v4.14.6`、`active/connected`。
- 查询非白名单 Agent `001` 被拒绝。
- RFC 5737 测试地址 `203.0.113.25` 完成 `not_blocked -> blocked -> not_blocked`，解封后独立查询仍为 `not_blocked`。

## 尚未完成

- `isolate_endpoint` 和恢复终端尚未连接真实执行器。演示 Agent 当前没有 `NET_ADMIN`，必须先设计保留 Wazuh 管理链路且带 TTL 自恢复的隔离脚本。
- `disable_account`、账号恢复、文件隔离/恢复、Suricata 规则启停仍未接入真实目标。
- `unblock_ip` 已具备受控工具与真实执行能力，但还需要增加面向操作员的“从既有封禁生成回滚计划”产品入口，不能让模型在首次事件响应中随意建议解封。
