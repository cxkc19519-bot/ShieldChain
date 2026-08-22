# ShieldChain XDR/探针规则 v8 评估报告（2026-08-22）

## 结论摘要

v8 只使用一批从未参与此前开发的 24 个 development 样本扩展规则。v7 基线仅分类 4/24；载荷审计发现 16 个 MSSQL 密码哈希提取绕过变体、3 个 MySQL 注释混淆 UNION 提取和 1 个原始 TCP 反弹 Shell 会话。v8 使用 4 条稳定证据规则覆盖这些家族，完整 development 回归达到 24/24，合成正常业务 PCAP 保持 0 告警。

冻结后使用全新 24 个 validation 样本独立验收，14/24 被分类、10/24 待研判，14 个样本产生 31 条 Suricata 告警。其中数据库攻击与数据提取 10 个，说明正文强证据规则在未见样本上产生了可观察的泛化收益。但该批次仍是攻击样本抽样且缺少真实正常业务集，不能据此计算准确率、精确率、召回率或生产误报率。

## 评估边界

- v8 开发只查看 `development-v8-24.txt` 的标签与载荷。
- 规则冻结后才运行 validation v8，运行中未修改规则。
- validation v8 使用固定盐值 `shieldchain-v8-20260822` 从剩余 validation 样本排序抽取。
- 本批与前七轮共 168 个 validation 样本零重叠。
- 机器结果与哈希先锁定，之后才读取原始文件名。
- validation 标签未用于回改 v8。
- final-blind 的 935 个样本仍未运行，清单时间戳未改变。
- 合成正常样本仅用于已知误报回归，不能代表校园生产流量。

## v8 规则增量

规则总数由 70 条增加到 74 条，其中 2 条为 `flowbits:noalert` 状态规则。新增规则：

1. HTTP POST 正文同时包含 `fn_varbintohexstr`、`password_hash`、`sys.sql_logins` 时，识别 MSSQL 密码哈希提取；按来源一分钟限频一次。
2. HTTP POST 正文包含混淆后的 `union + select + user(` 时，识别 MySQL 用户提取；按来源限频。
3. HTTP POST 正文包含 `union + select + information_schema` 时，识别 MySQL Schema 枚举；按来源限频。
4. 任意已建立 TCP 流出现 `bash: no job control in this shell` 时，识别原始反弹 Shell 会话；不依赖固定端口、IP 或文件名。

新增 `test_suricata_rule_metadata.py`，持续检查本地 SID 唯一性、保留范围和 `flowbits:noalert` 规则是否确实设置流状态。

## development 回归

固定清单：`development-v8-24.txt`

| 指标 | v7 基线 | v8 冻结候选 |
| --- | ---: | ---: |
| 样本数 | 24 | 24 |
| 已分类 | 4 | 24 |
| 待研判 | 20 | 0 |

- v7 基线：`run-20260822-142705`
- 第一轮 20 个漏检定向回归：`run-20260822-143830`
- MySQL 三样本修订回归：`run-20260822-144808`
- 合成正常业务回归：`run-20260822-145002`，0 条告警
- v8 完整 development 回归：`run-20260822-145025`

24/24 只表示对这批定向攻击家族的覆盖，不是独立准确率。

## 冻结信息

- 规则 SHA-256：`862c3b709629041e543669b157415923bbffcb37b777e83562e248b903e416a1`
- 流水线 SHA-256：`26492e175874a782af7a9b5ef74683cab9cdb9efd9d4bd56191d3c11dc3e1471`
- validation 清单 SHA-256：`8391d0aba6fa7c2062b293bf08209c3095354fe246085cdb050cc8b800edbc19`

## 独立 validation v8

- 清单：`validation-sample-v8-24.txt`
- 运行：`run-20260822-150020`
- 锁定结果：`validation-v8-locked-result.json`
- 锁定文件 SHA-256：`ef32264ebd7e7008bd03ccb8a2f832884357f5566b9e1f208b1f8fb6489200f8`

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 24 |
| 已分类 | 14（58.3%） |
| 待研判 | 10（41.7%） |
| 至少一条 Suricata 告警 | 14 |
| Suricata 告警总数 | 31 |

分类分布：

- 数据库攻击与数据提取：10
- 命令执行与反弹连接：1
- 命令执行：1
- 疑似 WebShell 交互：1
- Suricata 安全规则告警：1
- 网络行为待研判：10

## 标签审计

锁定后查看原始文件名：

- 可读命中包括 WebLogic 字节码反弹 Shell、Struts2-057、Fastjson CVE-2017-18349 和泛微 BeanShell RCE。
- 10 个数据库分类样本中多数原始名称为哈希或时间编号，不能仅凭名称确认子家族；分类依据是实际 SQL 提取载荷。
- 明确可读漏检包括 `IEX_powerup`、DedeCMS CVE-2018-9174、MySQL 布尔脱库、`ST_LatFromGeoHash` 错误注入、`WAIT_FOR_EXECUTED_GTID_SET` 错误注入，以及 CrystalShell SQL 管理行为。
- 其余 4 个待研判样本名称为哈希或时间编号，未强行赋予语义。

v7 的 5/24 与 v8 的 14/24 使用不同 validation 样本，不能把差值直接解释为准确率提升。v8 更强的同分布证据是：同一 development 清单从 4/24 提升到 24/24，并且新的 SQL 正文规则在 validation 中命中多个未见样本，同时良性反例保持 0 告警。

## 风险与下一步

1. validation 仍有 41.7% 待研判，PowerShell、DedeCMS、MySQL 函数变体和大型 WebShell 管理行为需要新的 development 样本支持。
2. `bash` job-control 横幅是强证据，但仍需真实运维终端流量验证误报风险。
3. SQL 正文规则应在真实 API、报表查询和数据库管理流量上建立正常基线。
4. 社区规则的 Fastjson 等信息告警仍需结合响应、DNS/RMI 回连或资产版本才能精确归因。
5. final-blind 只应在候选规则、真实正常流量集和验收指标最终冻结后运行一次。
