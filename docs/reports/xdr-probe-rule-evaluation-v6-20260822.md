# ShieldChain XDR/探针规则 v6 评估报告（2026-08-22）

## 结论摘要

v6 的重点不是增加攻击签名，而是修复 v5 暴露出的两类高风险误报：

1. 单次脚本 POST 返回 32 KiB 以上内容，会把正常报表下载误判为 WebShell。
2. 任意高熵 `fish=` 请求都会直接告警，缺少脚本端点与服务器响应的关联证据。

v6 删除单次大响应判定，并将 `fish=` 改为两阶段关联：客户端对脚本端点提交高熵参数时只设置 `flowbit`，只有同一流的服务端响应同时符合“16 位十六进制边界 + 长 Base64 内容”才产生 WebShell 告警。

在同一份可复现合成正常业务 PCAP 上，v5 产生 2 条告警并分类为“命令与 WebShell 行为”，v6 产生 0 条告警并降为“网络行为待研判”。在 18 个加密 WebShell development 样本上，v6 仍保持 18/18 分类覆盖。

冻结后使用全新 24 个 validation 样本独立验收，7/24 被分类、17/24 待研判，6 个样本产生 30 条 Suricata 告警。跨家族覆盖仍不足，不能称为生产级 XDR。

## 评估边界

- 规则开发只查看 development 标签和载荷。
- 合成正常 PCAP 只用于明确的误报反例，不属于攻击 validation。
- v6 规则与流水线冻结后才运行 validation v6 清单。
- validation v6 使用固定盐值 `shieldchain-v6-20260821` 从剩余样本中排序抽取。
- 本批 24 个样本与此前 120 个 validation 样本零重叠。
- 机器结果及哈希先锁定，之后才读取原始文件名。
- final-blind 的 935 个样本仍未运行。
- 单个合成正常 PCAP 不代表生产业务分布，仍不能计算误报率、准确率、精确率或召回率。

## v6 误报护栏

生成器：`scripts/nta/generate_benign_fixture.py`

生成器只写 PCAP 文件，不创建网络连接。PCAP 使用 RFC1918 地址并包含四种合成业务：

1. `/report.php` 的正常 POST 与 40,000 字节报表响应。
2. `/api/search` 的长 `fish=` 表单值。
3. `/search.php` 的长 `fish=` 表单值。
4. `/login.php` 的普通登录表单。

| 版本 | 运行 | 分类 | Suricata 告警 |
| --- | --- | --- | ---: |
| v5 冻结版 | `run-20260822-131322` | 命令与 WebShell 行为 | 2 |
| v6 冻结版 | `run-20260822-131245` | 网络行为待研判 | 0 |

该对比证明已消除这四类确定的合成误报，但不能外推为真实环境误报率为零。

## development 回归

固定清单：`development-v5-18.txt`（v6 沿用同一攻击开发回归清单）

| 指标 | v5 | v6 |
| --- | ---: | ---: |
| 样本数 | 18 | 18 |
| 已分类 | 18 | 18 |
| 待研判 | 0 | 0 |

v6 完整开发回归：`run-20260821-173817`

关键 GSL PHP XOR/Base64 样本在请求/响应关联后仍产生 1 条告警并归类为“命令与 WebShell 行为”。18/18 只表示定向开发集覆盖，不是独立准确率。

## 冻结信息

- 规则：`shieldchain-nta.rules.v6-frozen`
- 规则 SHA-256：`358e99f076736d60cb833674da4ab917ac290d1702a07e72a44233e1cb1299a3`
- 流水线：`nta_offline_pipeline.py.v6-frozen`
- 流水线 SHA-256：`e220047d82c2d8cf326cbf401de98af150d754a4c6e47553a8dd5c7d80ff2192`

## 独立 validation v6

清单：`validation-sample-v6-24.txt`

运行：`run-20260821-174702`

锁定结果：`validation-v6-locked-result.json`

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 24 |
| 已分类 | 7（29.2%） |
| 待研判 | 17（70.8%） |
| 至少一条 Suricata 告警 | 6 |
| Suricata 告警总数 | 30 |

分类分布：

- 疑似 WebShell 交互：4
- 命令与 WebShell 行为：1
- 疑似 Web 漏洞利用：1
- Suricata 安全规则告警：1
- 网络行为待研判：17

锁定文件 SHA-256：`011bb9dd3fa0a461fb45fd706b77a2bdb89bcc1fa9edc1e9491c27fc1e53fdbc`

## 标签审计

锁定机器结果后查看原始文件名：

- 可读命中包括 Godzilla 3.03 PHP、Struts2 RCE、蚁剑 PHP ROT13、蚁剑 ROT13/Base64 倒序编码、GSL 文件上传和菜刀 PHP5。
- 一个哈希命名样本被命中，但仅凭名称不能确认具体家族。
- 明确可读漏检为 `Response_Command_high_netUser.json.pcap`。
- 其余 16 个漏检名称多为哈希或时间编号，未仅凭文件名强行判定攻击语义。

v5 的 8/24 与 v6 的 7/24 来自不同验证样本，不能把差值解释为检测能力下降或准确率变化。v6 的主要可验证收益是同一正常反例从 2 条告警降为 0，同时保持 development 回归覆盖。

## 风险与下一步

1. validation 待研判率仍为 70.8%，跨家族检测覆盖不足。
2. 当前正常流量只有四类合成事务，无法代表文件上传、API、数据库、运维和长连接等真实业务。
3. 请求/响应 Base64 关联比单请求规则可靠，但仍需真实业务 PCAP 验证。
4. 下一轮只使用未参与 validation 的 development 样本扩展命令响应、框架漏洞和数据库家族。
5. 应逐步建立可信正常流量集，并按协议/业务类型报告告警率，而不是只统计攻击样本命中。
6. final-blind 在候选规则和正常流量评估方案最终冻结前继续封存。
