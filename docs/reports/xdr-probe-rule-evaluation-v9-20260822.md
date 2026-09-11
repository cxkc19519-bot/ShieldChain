# ShieldChain XDR/探针规则 v9 评估报告（2026-08-22）

## 结论摘要

v9 使用全新的 24 个 development 样本继续验证 v8。v8 基线已能分类 20/24，说明数据库正文强证据规则在更多混淆样本上具备复用性。剩余 4 个漏检分别为 MySQL 堆叠用户提取、Struts2-001 OGNL 路径读取、Oracle `DBMS_XMLGEN` 错误注入和 POP3 钓鱼邮件。v9 为这四类增加 4 条规则，并为钓鱼邮件增加独立中文分类与 ATT&CK `T1566.002`。完整 development 回归达到 24/24，合成正常 HTTP PCAP 保持 0 告警。

冻结后使用全新 24 个 validation 样本独立验收，16/24 被分类、8/24 待研判；16 个样本各产生 1 条告警，全部归为数据库攻击与数据提取。结果进一步支持 SQL 正文强证据的泛化性，但没有独立验证本轮钓鱼规则，且缺少正常邮件流量，不能声称生产可用。

## 评估边界

- v9 只查看 `development-v9-24.txt` 的标签与载荷进行开发。
- v9 规则与分类器冻结后才运行 validation v9。
- validation v9 使用固定盐值 `shieldchain-v9-20260822` 从剩余样本排序抽取。
- 本批与前八轮共 192 个 validation 样本零重叠。
- 机器结果和哈希先锁定，之后才读取原始文件名。
- validation 标签未用于回改 v9。
- final-blind 的 935 个样本仍未运行。
- 当前正常样本是 HTTP 合成事务，不覆盖正常 POP3/SMTP 邮件。

## v9 规则与分类增量

规则总数由 74 条增加到 78 条，其中 2 条为 `flowbits:noalert` 状态规则：

1. MySQL 表单中 `id=...%3Bselect...user%28%29` 的堆叠用户提取。
2. Struts2 正文中 `ServletActionContext + getRealPath` 的 OGNL 路径读取利用。
3. Oracle 正文中 `dbms_xmlgen.getxml + global_name + dual` 的错误注入提取。
4. POP3 服务端邮件正文中的十六进制整数 IP `/login` 链接，识别规避常规域名检查的钓鱼诱导。

分类器新增“钓鱼邮件与凭据诱导”，严重度 9，映射 `T1566.002`。规则完整性测试的最低规则数同步更新为 78。

## development 回归

固定清单：`development-v9-24.txt`

| 指标 | v8 基线 | v9 冻结候选 |
| --- | ---: | ---: |
| 样本数 | 24 | 24 |
| 已分类 | 20 | 24 |
| 待研判 | 4 | 0 |

- v8 基线：`run-20260822-151442`
- 四样本定向回归：`run-20260822-152536`
- 合成正常 HTTP 回归：`run-20260822-152733`，0 条告警
- v9 完整 development 回归：`run-20260822-152756`

24/24 仅表示该定向 development 批次覆盖，不是独立准确率。钓鱼规则尚无正常邮件语料回归。

## 冻结信息

- 规则 SHA-256：`0c87908e60f5b3d1f082292d55c3a75586c5682b5facceee488716eb4f31ec03`
- 流水线 SHA-256：`39f894d242c284a1b9e31fe15b39ec139df0f8f7805a3392ae8722adf5c2d3b5`
- validation 清单 SHA-256：`0e286e3e7bd675eb54829627cec77ef01bac1eb8ac615e14a23570edbd1949bd`

## 独立 validation v9

- 清单：`validation-sample-v9-24.txt`
- 运行：`run-20260822-153730`
- 锁定结果：`validation-v9-locked-result.json`
- 锁定文件 SHA-256：`e60488b0d7bf632b20ca42565a4dddc8aca46e4b766a79167729eb11eb8c02c3`

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 24 |
| 已分类 | 16（66.7%） |
| 待研判 | 8（33.3%） |
| 至少一条 Suricata 告警 | 16 |
| Suricata 告警总数 | 16 |

分类分布：

- 数据库攻击与数据提取：16
- 网络行为待研判：8

## 标签审计

锁定后读取原始文件名：

- 16 个命中样本的原始名称均为哈希或时间编号，未根据名称猜测具体数据库子家族；分类来自实际 SQL 提取规则。
- 明确可读漏检包括无响应 Windows `del` 命令、Oracle UNION 数据库枚举、Struts2-008 信息查询和 S2-046 漏洞探测。
- 其余 4 个待研判样本为时间编号，未强行赋予语义。
- 本批没有可读 POP3 钓鱼样本命中，因此不能用 validation v9 宣称钓鱼检测已泛化。

v8 的 14/24 与 v9 的 16/24 来自不同 validation 清单，不应直接解释为准确率提升。可验证的同批收益是 development 从 20/24 提升到 24/24；SQL 规则则在 validation v9 中形成 16 个独立的单告警命中。

## 风险与下一步

1. 建立正常 POP3/SMTP 邮件 PCAP，验证十六进制 IP 登录链接规则的误报率。
2. 使用新的 development 样本覆盖 Oracle UNION、Struts2-008/S2-046 与无响应命令行为。
3. 对无响应 `del/cp` 等短命令需要结合端点日志或可信工具上下文，避免网络单关键词误报。
4. 数据库规则需在真实 API、运维和报表业务流量上建立正常基线。
5. final-blind 只在候选规则与真实正常流量验收方案最终冻结后运行一次。
