# ShieldChain XDR/探针规则 v7 评估报告（2026-08-22）

## 结论摘要

v7 只使用新的 development 样本扩展规则，覆盖 ThinkPHP 远程代码执行、Windows/Linux 命令表单、Shiro `rememberMe` 反序列化、MSSQL/MySQL 布尔提取、GTID 错误注入、UNION 元数据提取以及 `INTO DUMPFILE` 写入 WebShell。

同一份 24 个 development 样本上，v6 基线分类 10/24，v7 冻结候选分类 23/24；唯一保留为待研判的是无响应的简单 `cp` 命令，因为仅依据 `data=cp` 告警容易误伤合法管理请求。MySQL 自动化探测样本的重复告警由 113 条降为 2 条，分类仍保持为数据库攻击。

冻结后使用全新 24 个 validation 样本独立验收，5/24 被分类、19/24 待研判，4 个样本产生 12 条 Suricata 告警。该结果说明定向开发覆盖显著提升，但跨家族泛化仍不足，不能称为生产级 XDR，也不能据此计算准确率、精确率或召回率。

## 评估边界

- 规则开发只查看 `development-v7-24.txt` 的标签和载荷。
- v7 规则、分类器和哈希冻结后才运行 validation v7。
- validation v7 使用固定盐值 `shieldchain-v7-20260822` 从剩余 validation 样本排序抽取。
- 本批 24 个样本与前六轮共 144 个 validation 样本零重叠。
- 机器结果和哈希先写入锁定文件，之后才读取原始文件名。
- validation 标签只用于事后审计，不用于修改 v7。
- final-blind 的 935 个样本仍未运行。
- 单个合成正常 PCAP 只能作为明确误报回归，不能代表生产正常流量分布。

## v7 规则增量

规则总数由 v6 的 54 条增加到 70 条定义，其中 2 条为 `flowbits:noalert` 状态规则。新增或强化的检测包括：

1. ThinkPHP `invokefunction/call_user_func_array` 与 `_method=filter` RCE。
2. `certutil -urlcache -split`、读取 `/etc/passwd`、删除 Windows 注册表键。
3. `dig` 请求与 DiG 响应横幅的双向关联，避免仅凭短命令直接告警。
4. Shiro 长 `rememberMe` 序列化载荷。
5. MSSQL `UNICODE(SUBSTRING(...SYSTEM_USER...))` 布尔提取。
6. MySQL `ELT(ORD(MID(...CURRENT_USER...)))`、GTID 错误注入和 UNION 元数据提取。
7. MySQL `INTO DUMPFILE` 写入服务端脚本。
8. 高频 SQL 探测按来源限频，降低告警风暴。

分类器还把带有 Struts、Fastjson、Shiro、WebLogic 等明确框架利用语义的签名归为“漏洞利用”；对仅有通用回显或信息告警的签名仍保持通用类别，不强行精确归因。

## development 回归

固定清单：`development-v7-24.txt`

| 指标 | v6 基线 | v7 冻结候选 |
| --- | ---: | ---: |
| 样本数 | 24 | 24 |
| 已分类 | 10 | 23 |
| 待研判 | 14 | 1 |

- v6 基线运行：`run-20260822-132217`
- v7 完整开发回归：`run-20260822-135346`
- v7 定向六样本回归：`run-20260822-134904`
- 合成正常业务回归：`run-20260822-135309`，0 条告警

23/24 仅表示对定向开发家族的覆盖，不是独立准确率。

## 冻结信息

- 规则 SHA-256：`3d5464fb60b561677cc2d27da5e97f8650617d54df964e001bccb278c03c55d0`
- 流水线 SHA-256：`26492e175874a782af7a9b5ef74683cab9cdb9efd9d4bd56191d3c11dc3e1471`
- validation 清单 SHA-256：`dd524a5eb2f64f18c1952649fa38d81723dbf5588240dc331b379ce8d08b6142`

## 独立 validation v7

- 清单：`validation-sample-v7-24.txt`
- 运行：`run-20260822-140330`
- 锁定结果：`validation-v7-locked-result.json`
- 锁定文件 SHA-256：`5d775afe1b0c9747c86dced6c19c9adc9e64f47e2f02316af8d91224b85edebe`

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 24 |
| 已分类 | 5（20.8%） |
| 待研判 | 19（79.2%） |
| 至少一条 Suricata 告警 | 4 |
| Suricata 告警总数 | 12 |

分类分布：

- 疑似 Web 漏洞利用：2
- 疑似 WebShell 交互：2
- Suricata 安全规则告警：1
- 网络行为待研判：19

## 标签审计

锁定机器结果后查看原始文件名：

- 可读命中包括蚁剑 JSP defineClass/zlib/Base64、蚁剑 PHP hex/Base64（由 Zeek 行为分类）以及 Struts2 S2-053 漏洞探测。
- 两个告警命中样本的名称为哈希，不能仅凭文件名确认具体家族。
- 明确可读漏检包括 JBoss CVE-2010-1871、Windows `reg query` 命令响应、MySQL `secure_file_priv/OUTFILE` getshell，以及 CVE-2020-2883 反弹 Shell。
- 其余 15 个待研判样本使用哈希或时间编号，未仅凭文件名强行赋予攻击语义。

v6 的 7/24 与 v7 的 5/24 来自不同 validation 样本，不能把差值解释为检测能力下降。v7 的可验证收益应以同一 development 清单从 10/24 到 23/24、同一 MySQL 样本从 113 条降到 2 条重复告警，以及良性回归保持 0 告警来表述。

## 风险与下一步

1. validation 待研判率为 79.2%，跨漏洞家族和命令协议覆盖仍不足。
2. JBoss 旧漏洞、`reg query`、MySQL OUTFILE 变体和 WebLogic/CVE-2020-2883 是下一轮 development 候选；不得再使用本轮 validation 样本调参。
3. 当前正常流量仍只有合成反例，尚无真实校园业务流量基线，不能估计误报率。
4. 高密度自动化扫描需继续采用聚合、限频和事件合并，避免规则命中数等同于事件数。
5. final-blind 必须在规则候选、正常流量评估方案和验收口径最终冻结后才能运行一次。
