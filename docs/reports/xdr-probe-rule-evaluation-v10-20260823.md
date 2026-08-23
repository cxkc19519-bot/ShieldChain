# XDR/探针规则 v10 独立验证报告（2026-08-23）

## 1. 验证目的

本轮验证用于检查 v10 冻结的 Suricata/Zeek 离线检测链路在未参与本轮调参的数据上的覆盖情况。先冻结代码、规则和镜像，再运行机器检测并锁定输出，之后才核对标签映射。`final_blind` 未运行。

## 2. 冻结状态

- Git 提交：`7974ef1`；
- 规则 SHA-256：`e4ee9be7800b2a39d3bf227c63d783186c8f7b2be6100d0af709dd1dea181d2b`；
- 流水线 SHA-256：`fffd10d94d432a967adc685dbdd7e3e91a2de724fda01ab5dc68c7537eff0cb7`；
- Suricata 镜像 ID：`sha256:11269002d0a4ba2628aced92de6e8d04895c0efa4f1318804addcdc7ec76dbf6`；
- Zeek 镜像 ID：`sha256:adf96607966a0ee61800ede343c8c1cfe744bbb0a6e9b600cdc4ffa997e0fda0`；
- 服务器冻结目录：`/home/user/jhk/nta-dataset-blind/evaluation/v10-freeze-20260823`。

冻结目录设为只读。检测容器使用 `--network none`，PCAP 未回放到校园网或生产网络。

## 3. 正常流量 validation

60 条正常 validation 均为本轮重新生成的隔离实验流量，不与 development PCAP 重复：

采集清单与 PCAP 重新计算校验结果：记录 60 条、大小/SHA-256 不一致 0。

| 协议 | 样本 | 安全告警 | 上下文观察 | 信息/解码事件 | 引擎失败 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HTTP | 12 | 0 | 0 | 149 | 0 |
| MariaDB | 12 | 0 | 0 | 279 | 0 |
| SMTP | 12 | 0 | 0 | 314 | 0 |
| DNS | 6 | 0 | 0 | 31 | 0 |
| SSH | 6 | 0 | 0 | 267 | 0 |
| SMB | 6 | 0 | 0 | 272 | 0 |
| Windows 管理 | 6 | 0 | 83 | 871 | 0 |
| 合计 | 60 | 0 | 83 | 2,183 | 0 |

结果：Suricata 60/60 成功、Zeek 60/60 成功，安全告警样本为 0/60。对“这批 validation 场景中的安全告警样本比例”，零事件的单侧 95% 精确上界约为 4.87%。该数字不是生产误报率。

- 运行：`/home/user/jhk/nta-benign-corpus-v10/validation-all-v10-analysis/run-20260823-134702`；
- 锁定摘要：`benign-validation-v10-locked-result.json`；
- 锁定摘要 SHA-256：`ab6f3461730ff389577067c1ab1b0758334c9ad2b1141cdbe3688a89d087b3a6`。

## 4. 攻击流量 validation

比赛 PCAP 的 validation 总数为 701。v1～v9 共使用 216 个唯一样本；v10 使用剩余的全部 485 个未使用样本，与旧清单交集为 0。

- 清单：`validation-sample-v10-remaining.txt`；
- 清单 SHA-256：`7e85bba2d38039181e119802136d503d087d0dd0c5ec38afe2a55c0c2032dd9c`；
- 五个并行批次各 97 条；
- 五批运行 ID：`run-20260823-135138`；
- 引擎失败：0/485；
- 得到攻击分类：387/485，覆盖率 79.79%，Wilson 95% 区间 75.99%–83.13%；
- 产生至少一条安全告警：366/485，覆盖率 75.46%，Wilson 95% 区间 71.44%–79.08%；
- 保守待研判：98/485，占 20.21%；
- 安全告警总数：1,765；
- 信息/解码事件：88,427。

### 分类分布

| 机器输出类别 | 样本数 |
| --- | ---: |
| 数据库攻击与数据提取 | 294 |
| 疑似 WebShell 交互 | 44 |
| 漏洞利用 | 16 |
| 命令执行 | 11 |
| 命令与 WebShell 行为 | 11 |
| Suricata 安全规则告警 | 6 |
| 命令执行与反弹连接 | 3 |
| 扫描与侦察 | 2 |
| 网络行为待研判 | 98 |

主要规则命中包括 MSSQL 密码哈希 SQL 注入、ORDER BY 注释探测、大 HTTP POST、URI 路径穿越、异常 User-Agent、MySQL 混淆 UNION、WebShell、Struts/JBoss/Shiro/WebLogic 利用等。

锁定摘要为 `/home/user/jhk/nta-dataset-blind/evaluation/attack-validation-v10-locked-result.json`，SHA-256 为 `7a6e0cff8837467a730e146b0814062564b9ed6e43fd77e405bf5e4919e4c384`。

## 5. 指标边界

标签映射完整覆盖 485/485，但仅包含匿名文件名、原始相对路径和 PCAP SHA-256，没有逐样本攻击类型字段；多数原始路径也是随机文件名。因此：

- 79.79% 是“ShieldChain 给出攻击分类”的覆盖率，不是分类准确率；
- 75.46% 是“至少产生一条安全告警”的覆盖率，不是精确率或召回率；
- 无法从现有真值计算按攻击家族的混淆矩阵；
- 正常流量来自隔离实验室，不代表校园网或生产环境分布；
- v10 validation 结果不用于针对这些样本继续调规则；
- `final_blind` 继续封存，只有在验收方案最终确定后才能运行一次。

## 6. 结论

v10 在 60 条独立正常场景中未产生安全误报，同时在 485 条未参与前九轮验证的比赛 PCAP 中，对 387 条给出攻击分类、366 条产生安全告警，且 545 条 validation PCAP 的 Suricata/Zeek 执行均无失败。当前主要缺口是 98 条待研判样本和缺少官方逐类真值；不能据此宣称达到生产级 XDR 或给出“准确率”。
