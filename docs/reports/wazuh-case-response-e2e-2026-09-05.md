# Wazuh 案件真实处置闭环验收（2026-09-05）

## 结论

学校服务器上的 ShieldChain 已跑通一条受控实验室闭环：Wazuh 规范化告警入库 → 操作员显式启动调查 → 本地 Qwen 多智能体按需调用只读工具 → 响应规划智能体生成严格候选 → 服务端绑定案件与确认事实 → 操作员接受计划 → 独立批准 `block_ip` → nftables 执行 → 独立查询验证 → 60 秒 TTL 自动清理。

本次成功验收目标固定为 RFC 5737 文档地址 `203.0.113.25`，不是实际公网或校园网地址。执行器、后端、前端和本地模型服务在验收后均保持健康。

## 成功样本

- Wazuh alert：`1425970e-0659-443d-8821-a12c66f206d0`
- Wazuh case：`09fba245-186c-498d-978f-e1c527296633`
- Agent run：`c56d2766-5609-4f1d-82ef-7ed2046cc69f`
- Response plan：`03c1acea-bdbd-4480-97a3-6bd5ad9605a9`
- Trusted tool call：`7080075a-9b59-40e5-9350-e3a68f9bf73c`
- 模型：`shieldchain-qwen3-30b`
- 动作：`block_ip`，目标 `203.0.113.25`，TTL 60 秒
- 工具最终状态：`succeeded`
- 执行尝试：`succeeded`
- 验证结果：`verified`
- TTL 结果：最终验收脚本通过执行器 Unix socket 返回 `firewall_status=not_blocked`，退出码为 0

## 现场发现并修复的问题

1. React 仓库原先只认可旧 `InvestigationRunRow`，导致已绑定的 Wazuh 案件在接受计划时返回 `ReactLoopNotFound`。修复后同时支持精确的同租户 `WazuhCaseRunRow` 绑定。
2. `NftablesAdapterProvider` 原先依赖模拟适配器作为前置条件，真实 Wazuh 运行因此被错误标记为 `trusted_adapter_unavailable`。修复后只有存在精确 Wazuh 运行绑定时才提供 firewall-only 真实适配器，未绑定运行仍拒绝。
3. 验收脚本原先复用固定规则 ID，会被 Wazuh 相关性窗口合并到旧案件；现改为每次生成唯一规则 ID。
4. 验收脚本对验证枚举误写为 `matched`；系统实际且正确的公开值为 `verified`，断言已修正。

失败尝试保留在数据库审计中，没有删除或改写；前两次计划均在安全边界停止，未执行防火墙动作。

## 自动化验证

- 本次功能相关测试：43 项通过；
- React/Wazuh 运行绑定相关测试：30 项通过；
- Wazuh firewall provider 路由相关测试：31 项通过；
- 前端：30 个测试文件、120 项测试通过，生产构建通过；
- 最终完整后端回归：1232 项通过、33 项按环境跳过、0 项失败（331.11 秒）。

## 不能据此宣称的能力

- 不能宣称允许处置任意公网、校园网或生产地址；
- 不能宣称终端隔离、账号禁用已接入真实 EDR/目录服务；
- 不能把模型建议当作攻击事实或人工授权；
- 不能把一次实验室链路验收等同于生产级 RBAC、双人审批、HA、灾备和全网实时流量验收。
