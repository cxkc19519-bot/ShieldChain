# ShieldChain XDR/探针规则 v4 评估报告（2026-08-21）

## 结论摘要

v4 将自定义 Suricata 规则从 37 条扩展到 48 条，并增强 Zeek 的脚本端点交互行为判断。在 23 个只用于开发的目标样本上，分类覆盖由 v3 基线的 11/23 提升到 23/23；在冻结规则后抽取的全新 24 个 validation 样本上，7/24 被分类、17/24 待研判。

独立验证只比 v3 的另一批验证样本（6/24）增加 1 个命中。两批样本不同，不能把这一差值直接解释为统计意义上的准确率提升。结果说明 v4 对目标家族有效，但跨家族泛化仍不足，不能称为生产级 XDR。

## 评估边界

- 仅在比赛方 NTA PCAP 的项目自建 development/validation 划分中测试。
- 规则开发只查看 development 标签和载荷。
- v4 冻结后才创建并运行 validation v4 清单。
- validation v4 使用固定盐值 `shieldchain-v4-20260821` 对剩余样本名排序选取，未读取原始标签。
- 与前三批验证清单共 72 个样本零重叠。
- final-blind 的 935 个样本未运行。
- 没有可信正常流量集，因此不能计算准确率、精确率或误报率。

## v4 新增能力

1. 菜刀 JSP/JSPX 命令协议识别。
2. JspSpy WebShell 端点识别。
3. 脚本端点中 `data=` 命令表单参数识别。
4. MySQL `extractvalue` 错误注入与嵌套 UNION 用户提取。
5. MSSQL 密码哈希错误提取。
6. Spring SpEL `Runtime.getRuntime().exec` 命令执行。
7. BeanShell servlet 暴露与命令执行（含缺失握手方向时的双向 TCP 兜底）。
8. Zeek 多次小请求/大响应脚本端点交互检测。
9. 命令执行、数据库攻击和弱密码告警的中文分类与 ATT&CK 映射。
10. 运行输出明确区分分类、告警数和引擎退出码。

## development 回归

固定清单：`development-v4-23.txt`

| 指标 | v3 基线 | v4 |
| --- | ---: | ---: |
| 样本数 | 23 | 23 |
| 已分类 | 11 | 23 |
| 待研判 | 12 | 0 |
| 至少一条 Suricata 告警 | 10 | 22 |
| Suricata 告警总数 | 85 | 107 |

v3 基线运行：`run-20260821-160312`

v4 完整回归：`run-20260821-162452`

开发集结果只说明规则覆盖了用于调试的家族，不能用来证明泛化能力。

## 冻结信息

- 规则：`shieldchain-nta.rules.v4-frozen`
- 规则 SHA-256：`0db825db024fcc3b749d4efcd223487b1f7e87b0c2b116c53e1bd0e83238439b`
- 流水线：`nta_offline_pipeline.py.v4-frozen`
- 流水线 SHA-256：`85a7dbd3b26324b4a870c81e015982c201867d2eeb7d1b6d8b6b125d63062ac7`

## 独立 validation v4

清单：`validation-sample-v4-24.txt`

运行：`run-20260821-163407`

锁定结果：`validation-v4-locked-result.json`

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 24 |
| 已分类 | 7（29.2%） |
| 待研判 | 17（70.8%） |
| 至少一条 Suricata 告警 | 7 |
| Suricata 告警总数 | 70 |

分类分布：

- 疑似 WebShell 交互：1
- 命令与 WebShell 行为：2
- 漏洞利用：1
- 疑似 Web 漏洞利用：1
- Suricata 安全规则告警：2
- 网络行为待研判：17

锁定文件 SHA-256：`6dc075e114646b601ead7a1a32d178058c33518fd7c74c9cd369d907495e485f`

## 标签审计

锁定机器结果后查看原始文件名：

- 可直接识别语义的 7 个文件名中，6 个被检测：Godzilla ASP、未授权写 WebShell、WebLogic、冰蝎 JSPX、Godzilla ASHX、菜刀 ASPX。
- 1 个可读标签样本漏检：PHP 大马登录后交互。
- 其余 17 个文件名为哈希或时间编号，不能仅凭名称判断具体攻击家族，未强行给出“正确/错误”结论。

## 风险与下一步

1. validation 待研判率仍为 70.8%，规则覆盖不足。
2. BeanShell 双向 TCP 兜底与脚本命令参数规则需要正常业务流量验证误报。
3. 某些 WebShell 单样本产生大量重复告警，应在事件聚合层保留原始计数、对签名去重。
4. 下一轮应从未使用的 development 样本中抽取 PHP 大马、加密 WebShell、框架利用和数据库攻击家族，不能根据本次 validation 样本逐个调规则。
5. 引入正常 HTTP、数据库和运维命令流量后，才能计算误报率并调整阈值。
