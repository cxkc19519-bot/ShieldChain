# Wazuh 只读告警接入

> 文档状态：当前参考（更新于 2026-09-05）。告警接收、显式案件调查和人工审批的实验室真实防火墙链路已经完成服务器验收；接收入库本身始终是被动的，不会自动运行模型或执行处置。

## 目的

Wazuh Manager 将达到最低等级的告警通过受控 Webhook 转发给 ShieldChain。ShieldChain 完成鉴权、去重、时间窗口关联和持久化，再向实时告警页面、运营 MCP 和多智能体报告提供公开数据。

## 组件

- Windows Wazuh Agent：收集主机日志、文件完整性和安全事件；
- Wazuh Manager：解析规则并生成告警；
- Wazuh Indexer/OpenSearch：保存和检索告警；
- `scripts/wazuh/custom-shieldchain`：Manager 侧转发适配器；
- ShieldChain Wazuh API：接收、校验和持久化；
- 实时告警与运营报告页面：人工复核和分析。

## 配置

在 ShieldChain 私有 `.env` 中设置：

```dotenv
WAZUH_WEBHOOK_TOKEN=<长随机值>
WAZUH_REVIEW_MIN_SEVERITY=12
WAZUH_REVIEW_CORRELATION_WINDOW_SECONDS=900
```

Manager 侧适配器使用相同 Token，并只配置 ShieldChain 后端的受限地址。不要把 Token 写进仓库、镜像或聊天记录。

## 处理流程

1. 校验 Token、内容类型和请求大小；
2. 校验告警模式、时间、来源和等级；
3. 按来源告警 ID 或稳定摘要实现幂等；
4. 在关联窗口内归并同类资产和规则；
5. 保存待人工复核记录；
6. 向只读 `alerts`/`events` MCP 提供裁剪结果；
7. 操作员在实时告警页明确点击“启动智能体调查”，系统才创建唯一的案件运行、确认告警证据副本和公开审计记录；
8. 多智能体按需分析并生成报告。只有案件证据中的 IPv4 目标位于服务端允许网段时，响应规划智能体才可提出 `block_ip`；
9. 操作员必须先接受响应计划，再对每个变更工具调用独立审批；可信工具网关执行后必须重新查询并记录验证结果。

## 验证

```powershell
conda run -n ShieldChain python -m pytest backend/tests/integration/api/test_wazuh_ingestion.py -q
```

服务器实验室可运行完整受控验收。脚本只允许固定 RFC 5737 地址 `203.0.113.25`，但会真实写入一条 60 秒 nftables 规则，因此必须由获授权操作员显式加入 `--execute`：

```bash
cd /home/user/jhk/shieldchain
docker run --rm \
  --network container:shieldchain-backend-1 \
  --env-file .env \
  -v shieldchain_shieldchain-executor-socket:/run/shieldchain-executor:ro \
  -v "$PWD/scripts/verify_wazuh_response_e2e.py:/verify.py:ro" \
  shieldchain-backend:local \
  python /verify.py --execute --ttl 60
```

成功输出应依次包含 `alert_ingested`、`investigation_complete`、`plan_checked`、`plan_accepted`、`tool_approved`、`execution_verified` 和 `ttl_cleanup_verified`。最后一步会通过只读挂载的 Unix socket 独立确认 `firewall_status=not_blocked`；日志和输出不得包含 Webhook Token 或执行器令牌。

还应验证错误 Token、重复告警、低等级告警、超大请求、格式错误、重启持久化和前端中文错误状态。

## 安全边界

- 只读取和转发告警，不修改 Wazuh 规则或 Agent；
- 原始告警载荷不直接交给模型，先做字段裁剪；
- 告警进入报告不等于已确认威胁；
- 模型只能提出候选；目标、工具、参数模式、证据绑定、允许网段和 TTL 均由服务端重新检查；
- 真实封禁必须经过计划接受、独立工具审批、可信工具网关和执行后验证；
- 当前真实连接器仅覆盖实验室 nftables `block_ip`，终端隔离和账号禁用仍未接入真实系统。
