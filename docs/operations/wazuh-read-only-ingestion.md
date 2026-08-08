# Wazuh 只读告警接入

> 文档状态：当前参考（更新于 2026-08-08）。告警已进入实时告警和安全运营报告链路；真实自动处置仍未启用。

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
7. 报告智能体按需分析，不自动执行处置。

## 验证

```powershell
conda run -n ShieldChain python -m pytest backend/tests/integration/api/test_wazuh_ingestion.py -q
```

还应验证错误 Token、重复告警、低等级告警、超大请求、格式错误、重启持久化和前端中文错误状态。

## 安全边界

- 只读取和转发告警，不修改 Wazuh 规则或 Agent；
- 原始告警载荷不直接交给模型，先做字段裁剪；
- 告警进入报告不等于已确认威胁；
- 响应规划智能体只能提出建议；
- 真实封禁或隔离必须另行审批并经可信工具网关验证。
