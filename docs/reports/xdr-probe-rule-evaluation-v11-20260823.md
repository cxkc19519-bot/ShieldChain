# XDR/探针规则评估 v11（2026-08-23）

## 结论

v11 只使用项目自建 development 划分分析与调参，没有读取或运行 validation 与 final-blind。候选规则在 701 条攻击 development 上将分类覆盖从 v10 冻结基线的 585/701（83.45%）提高到 620/701（88.45%），净增 35 条、5.00 个百分点；安全告警样本从 567/701（80.88%）提高到 602/701（85.88%），同样净增 35 条、5.00 个百分点。

候选规则同时在 180 条正常 development 上回归，安全告警样本为 0/180；攻击和正常两组的 Suricata/Zeek 引擎失败均为 0。这个结果只说明新增规则通过了当前开发护栏，不代表生产误报率为零，也不是独立验证结果。

## 评估边界

- 攻击语料：比赛方 NTA PCAP 的项目自建 development，701 条。
- 正常语料：ShieldChain 隔离实验室生成的七类 development，180 条。
- 调参允许：仅 development。
- 未触碰：项目自建 validation、final-blind。
- 检测依据：Suricata 规则输出与 Zeek 协议元数据；运行时不使用文件名标签。
- 规则不会自动阻断，只生成待研判事件。

## v10 冻结基线

v10 基线使用冻结文件：

- `/home/user/jhk/nta-dataset-blind/evaluation/v10-freeze-20260823/shieldchain-nta.rules.v10-frozen`
- `/home/user/jhk/nta-dataset-blind/evaluation/v10-freeze-20260823/nta_offline_pipeline.py.v10-frozen`

完整 701 条攻击 development 基线：

| 指标 | v10 |
| --- | ---: |
| 分类样本 | 585/701（83.45%） |
| 安全告警样本 | 567/701（80.88%） |
| 待研判 | 116 |
| 引擎失败 | 0 |

116 条待研判样本均有 Zeek 连接和 HTTP 记录，说明主要差距是检测语义而非 PCAP 无法解析。其 75,815 条原始 Suricata 告警几乎全部是离线 PCAP 的 IPv4/TCP 校验和解码提示，不能当成安全命中。

## v11 新增能力

规则定义从 78 条增加到 95 条，其中 2 条 `flowbits:noalert` 只设置关联状态。新增规则覆盖：

- MySQL `MAKE_SET` 布尔注入、`RLIKE SLEEP` 和 `BENCHMARK/MD5` 时间注入；
- MSSQL `xp_dirtree`、`xp_fileexist` 带外探测；
- Oracle `CTXSYS.DRITHSX.SN` 错误注入；
- OAuth `response_type=${...}` SpEL 探测；
- Struts redirect OGNL 与 ValueStack/OgnlUtil 利用；
- ThinkPHP `_method=filter` 与 `passthru` 命令执行；
- Fastjson `java.net.Inet4Address` DNSlog 回连；
- WebLogic WSAT Registration 端点；
- Tomcat Manager 默认 `tomcat:tomcat` 凭据；
- PHP/JSP WebShell 管理面板响应指纹；
- 脚本端点中的扩展命令表单与 wget 下载。

对 46 条带可读开发标签的待研判样本分两轮定向检查，首轮恢复 27 条，第二轮再恢复 8 条。剩余 11 条主要是单一厂商上传、菜刀数据库操作和差异较大的大马界面，没有继续逐文件硬编码。

## 完整 development 结果

| 指标 | v10 | v11 | 变化 |
| --- | ---: | ---: | ---: |
| 分类样本 | 585/701 | 620/701 | +35 |
| 分类覆盖 | 83.45% | 88.45% | +5.00 个百分点 |
| 分类覆盖 Wilson 95% 区间 | — | 85.87%–90.60% | — |
| 安全告警样本 | 567/701 | 602/701 | +35 |
| 安全告警覆盖 | 80.88% | 85.88% | +5.00 个百分点 |
| 告警覆盖 Wilson 95% 区间 | — | 83.10%–88.26% | — |
| 待研判 | 116 | 81 | -35 |
| 引擎失败 | 0 | 0 | 0 |

v11 分类分布：

| 分类 | 数量 |
| --- | ---: |
| 数据库攻击与数据提取 | 421 |
| 网络行为待研判 | 81 |
| 疑似 WebShell 交互 | 45 |
| 命令执行 | 35 |
| 漏洞利用 | 34 |
| 命令与 WebShell 行为 | 30 |
| Suricata 安全规则告警 | 28 |
| 命令执行与反弹连接 | 14 |
| 其他分类合计 | 13 |

## 正常 development 护栏

Linux 服务流量 162 条与 Windows 管理流量 18 条合并为 180 条正常 development。使用相同 v11 候选规则运行：

- 双引擎成功：180/180；
- 安全告警样本：0/180；
- 引擎失败：0；
- 原始信息/解码器事件仍保留用于审计，但不升格为安全告警。

0/180 不能解释为生产误报率为零。正常语料是隔离实验室场景，覆盖范围和局限见 `docs/operations/benign-traffic-baseline.md`。

## 锁定产物

- 规则：`/home/user/jhk/nta-dataset-blind/evaluation/v11-candidate-rules.rules`
  - SHA-256：`21a4711aabb5358c325ff52f1aaacf453a8d8fca38ebfaf05a9bbceb1cab72f8`
- 攻击事件：`/home/user/jhk/nta-dataset-blind/evaluation/v11-development-candidate-events.jsonl`
  - SHA-256：`601ff1bed50773d09485445b91410de26563871c72c5d690cc42159675f04001`
- 正常事件：`/home/user/jhk/nta-benign-corpus-v10/development-all-v11-analysis/benign-development-v11-events.jsonl`
  - SHA-256：`36c4619af618e7fb752c84af3bf972c25d440e2a60d9ca5194ccb5eb6f5589c7`
- 锁定摘要：`/home/user/jhk/nta-dataset-blind/evaluation/v11-development-locked-result.json`
  - SHA-256：`8c9a0fdd975417d2108552aa42951fe9ee3e45bb61dcebe4a654936e37c4071a`

## 下一步

本报告记录的是 final-blind 启封前的 development 阶段，不应据此宣称独立准确率。v11 后续已在同日完成规则、代码、镜像和方案冻结，并一次性运行 935 条 final-blind；最终结果、哈希和结论边界见 `docs/reports/xdr-probe-final-blind-v11-20260823.md`。final-blind 已消耗，不得用于回改 v11。
