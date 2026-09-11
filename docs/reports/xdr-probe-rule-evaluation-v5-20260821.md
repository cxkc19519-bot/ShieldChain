# ShieldChain XDR/探针规则 v5 评估报告（2026-08-21）

## 结论摘要

v5 将自定义 Suricata 规则从 48 条扩展到 53 条，并为 Zeek 增加单次脚本请求与超大响应的 WebShell 行为检测。在 18 个只用于开发的加密 WebShell 和大马目标样本上，分类覆盖由 v4 基线的 15/18 提升到 18/18。

冻结 v5 后，在全新且未参与调参的 24 个 validation 样本上，8/24 被分类、16/24 进入待研判；6 个样本产生 Suricata 告警，共 36 条。该结果说明新增规则能够识别部分加密 WebShell 和大响应交互，但跨家族覆盖仍有限，不能称为生产级 XDR。

## 评估边界

- 仅使用比赛方 NTA PCAP 的项目自建 development/validation 划分。
- 规则开发只查看 development 标签和载荷。
- v5 规则与流水线冻结后才运行 validation v5 清单。
- validation v5 使用固定盐值 `shieldchain-v5-20260821` 从未使用样本中排序抽取。
- 本批 24 个样本与此前使用的 96 个 validation 样本零重叠。
- 机器输出和哈希先锁定，之后才读取原始文件名做人工审计。
- final-blind 的 935 个样本仍未运行。
- 没有可信正常流量集，因此不能计算准确率、精确率、召回率或误报率。

## v5 新增能力

1. ASPX `eval` 与 `FromBase64String` WebShell 装载行为。
2. 高熵 `fish=` 参数的加密 WebShell 交互。
3. `Backdoor`、`wso`、`b374k` 等多家族 WebShell 管理 Cookie。
4. RC-SHELL 和 PHP-SHELL HUNTER 响应标记。
5. Zeek 对脚本端点单次 POST 且响应不小于 32 KiB 的行为检测。
6. 新增对应分类回归测试，覆盖大响应脚本端点。

## development 回归

固定清单：`development-v5-18.txt`

| 指标 | v4 基线 | v5 |
| --- | ---: | ---: |
| 样本数 | 18 | 18 |
| 已分类 | 15 | 18 |
| 待研判 | 3 | 0 |

v4 基线运行：`run-20260821-165030`

v5 目标规则验证：`run-20260821-165909`

v5 完整开发回归：`run-20260821-170037`

18/18 是经过定向开发后的开发集覆盖，不是独立准确率，也不代表真实流量效果。

## 冻结信息

- 规则：`shieldchain-nta.rules.v5-frozen`
- 规则 SHA-256：`35bd96c2a8b5657359a4a9d301e56654081f5d1b8578c2a2a0458d8f82b9eeca`
- 流水线：`nta_offline_pipeline.py.v5-frozen`
- 流水线 SHA-256：`af7b9ebe298a4c53c10f3e1c90a4d35e3ab84f0ac50632291eebf920ed7d6269`

## 独立 validation v5

清单：`validation-sample-v5-24.txt`

运行：`run-20260821-170758`

锁定结果：`validation-v5-locked-result.json`

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 24 |
| 已分类 | 8（33.3%） |
| 待研判 | 16（66.7%） |
| 至少一条 Suricata 告警 | 6 |
| Suricata 告警总数 | 36 |

分类分布：

- 命令与 WebShell 行为：3
- 疑似 WebShell 交互：2
- 疑似 Web 漏洞利用：2
- Suricata 安全规则告警：1
- 网络行为待研判：16

锁定文件 SHA-256：`f5fdd7cd92cf745d66e006dd4ab808245f1403d16736bade8f04c900bdcf71ca`

## 标签审计

锁定机器结果后查看原始文件名：

- 命中可识别家族包括蚁剑 PHP XOR、蚁剑 PHP AES/Base64、PHP 大马、Behinder v2 JSP 和 Elasticsearch CVE-2015-1427。
- 漏检一个名称为 `webshell通信.pcap` 的样本。
- 多个 `.json.pcap` 或时间编号样本仅凭文件名无法可靠判断具体攻击家族，未强行给出“正确/错误”结论。

v4 与 v5 使用不同的独立验证样本，因此 7/24 与 8/24 只能作工程观察，不能直接解释为统计意义上的准确率提升。

## 风险与下一步

1. validation 待研判率仍为 66.7%，跨家族覆盖不足。
2. 高熵 `fish=` 与 32 KiB 大响应规则可能命中正常上传、下载或管理接口，必须用正常 HTTP/数据库/运维流量验证误报。
3. WebShell 样本可能产生重复告警，事件聚合层应保留原始计数并对签名去重。
4. 不允许根据本次 validation v5 的漏检样本逐个调整 v5；下一轮规则开发应使用尚未使用的 development 样本。
5. 下一阶段优先建立可信正常流量基线，再评估候选规则的误报风险。
6. final-blind 在规则和评估方案最终冻结前继续封存。
