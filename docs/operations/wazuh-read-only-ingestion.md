# Wazuh 只读告警接入

## 状态与边界

ShieldChain 已提供 Wazuh 告警收件箱：`POST /api/v1/integrations/wazuh/alerts` 接收经过 Wazuh Manager 自定义集成脚本标准化后的告警，按 `tenant_id + external_id` 去重并持久化。它只接收最小研判字段；不接收原始日志正文，不访问 Windows 主机，不调用 Wazuh Active Response，也不创建自动处置。

当前收件箱和既有“仿真调查”刻意隔离。真实告警进入收件箱后应由下一阶段的真实事件调查流程处理，不能复用仿真防火墙封禁。

## ShieldChain 配置

在 ShieldChain 的 `.env` 中设置一个随机、高熵、仅用于此 webhook 的值：

```dotenv
WAZUH_WEBHOOK_TOKEN=<long-random-secret>
```

不要把此值提交到 Git、填入 `.env.example`、浏览器、Wazuh 日志或截图。未配置时入口以 `503 wazuh_ingestion_unconfigured` 失败关闭；令牌错误返回 `401`。

## Wazuh Manager 配置

Wazuh 的 Integrator 支持以 `custom-` 前缀加载自定义集成：第一参数为 JSON 告警文件，第二参数为 `api_key`，第三参数为 `hook_url`。官方文档说明了这一契约和脚本位置。 [Wazuh External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

将仓库中的 `scripts/wazuh/custom-shieldchain` 复制到 Wazuh Manager 的 `/var/ossec/integrations/custom-shieldchain`，依照 Wazuh 的运行账户、属组和权限要求设置权限。脚本只选取规则、MITRE、主机、进程和网络五元组等最小字段，再 POST 到 ShieldChain。

在 Wazuh Manager 的 `/var/ossec/etc/ossec.conf` 添加类似配置，并将占位符替换为 ShieldChain 的私网 HTTPS 地址和刚生成的 webhook 令牌：

```xml
<integration>
  <name>custom-shieldchain</name>
  <hook_url>https://shieldchain.internal:8000/api/v1/integrations/wazuh/alerts</hook_url>
  <api_key>WAZUH_WEBHOOK_TOKEN_VALUE</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

先从高严重度（例如 `level >= 10`）开始，稳定后再逐步扩大范围。Wazuh 默认将告警写入 `alerts.json`，Integrator 读取该 JSON 并可转发到外部系统。 [Wazuh Alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)

## 验证顺序

1. 在隔离网络启动 Wazuh Manager、Windows Wazuh Agent 和 Sysmon；仅启用需要的 Sysmon 通道。
2. 配置 Wazuh Manager 的自定义集成，确认 Manager 到 ShieldChain 仅能访问 webhook 地址。
3. 触发一条无害测试告警，检查 `GET /api/v1/integrations/wazuh/alerts` 是否仅出现一条记录。
4. 重放同一告警，确认 `external_id` 去重，不产生第二条记录。
5. 审核字段、留存周期和访问权限后，再实现真实事件调查与人工审批闭环。

不要配置 Wazuh Active Response 来调用 ShieldChain；Active Response 是会在端点执行命令的另一条能力，不属于本接入范围。