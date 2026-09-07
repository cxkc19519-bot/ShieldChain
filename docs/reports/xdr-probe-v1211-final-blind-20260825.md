# XDR/探针 v12.1.1 CTU-13 final-blind 验收报告

日期：2026-08-25

## 1. 结论摘要

ShieldChain 使用冻结的 v12.1 检测规则和 v12.1.1 流式分类器，对 CTU-13 场景 9、10、11 的三个 Botnet-only PCAP 完成一次性 final-blind 验收。三个场景的 Suricata 与 Zeek 均成功退出，3/3 生成唯一事件并给出明确安全分类。

机器事件、清单、运行日志、候选哈希以及 56 个原始引擎文件的 SHA-256 在读取 final-blind BinetFlow 标签前已复制到只读目录。标签启封后确认三个场景均包含 Botnet 流。因此本轮证明的是 3/3 场景级恶意活动覆盖，不是逐流准确率、召回率或生产误报率。

## 2. 输入与隔离

| 场景 | PCAP 大小 | PCAP SHA-256 |
| ---: | ---: | --- |
| 9 | 1,126,596,020 字节 | 9f9cfb7313e4ef69a21be6500dff2dc1883bc7799e245e898b47bb8839a4da70 |
| 10 | 70,688,336,180 字节 | e0880092f58c73edf82f4da942b9fd3536883ef8f57b6ce3a10293da4a13c2c9 |
| 11 | 4,263,638,204 字节 | a2f41aa220cfd37d7b408b29686e13b46a92ac0452428c79e24577e0425c4933 |

三个划分按完整场景隔离，final-blind 与 development、validation 的场景交集均为 0。运行前重新核对三条 PCAP 的大小与 SHA-256，并确认 final-blind 标签文件不存在。

场景 10 的约 70.7 GB 文件是从 CTU-13 官方公开数据归档下载并保存在服务器的原始 PCAP，不是 ShieldChain 分析时生成的文件。本轮 PCAP、Zeek/Suricata 输出和标签始终只在服务器 /home/user/jhk/security-datasets 下处理，没有下载到本机。

## 3. v12.1.1 流式修订

第一次 final-blind 执行在场景 10 的 Suricata 和 Zeek 原始输出已完成后，旧分类器尝试一次性载入约 75 GB eve.json，进程内存升至约 15 GB 且继续增长。任务在生成场景 10 机器事件前安全终止，标签仍未读取，场景 9、10 的原始引擎输出被保留。

v12.1.1 只修改性能实现：

- Suricata JSONL 改为逐行过滤和聚合，不把整个 eve.json 放入内存；
- Zeek conn.log 改为多遍流式迭代，不再一次性建立全部行列表；
- 只保留完整告警计数、唯一签名计数和前 50 条原始证据签名；
- Suricata 规则、行为阈值和分类口径均未改变。

冻结前使用既有原始引擎输出完成严格回归：

| 集合 | 样本 | 与 v12.1 不一致 |
| --- | ---: | ---: |
| 自建正常 development | 180 | 0 |
| CTU-13 development | 7 | 0 |
| CTU-13 validation | 3 | 0 |
| 合计 | 190 | 0 |

比较字段包括分类、严重度、ATT&CK、Suricata 安全告警数和发现说明。场景 9 也在恢复前复核为原分类。最终处理期间 Python 内存稳定在约 234 MB，没有再出现失控增长。

## 4. 机器输出

| 场景 | 家族（标签启封后） | 机器分类 | 严重度 | ATT&CK | 安全告警 |
| ---: | --- | --- | ---: | --- | ---: |
| 9 | Neris | 疑似 HTTP 命令控制或数据外传 | 10 | T1071.001、T1041 | 63 |
| 10 | Rbot | 疑似 IRC 命令控制 | 10 | T1071 | 1,368 |
| 11 | Rbot | 疑似 IRC 命令控制 | 10 | T1071 | 24 |

引擎与协议记录：

| 场景 | Suricata 原始告警 | 信息类事件 | Zeek conn | Zeek HTTP | Zeek DNS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 9 | 121,968 | 121,905 | 137,838 | 17,152 | 225,059 |
| 10 | 123,501,575 | 123,500,207 | 7,538,563 | 50 | 2,516 |
| 11 | 7,864,784 | 7,864,760 | 126,293 | 3 | 165 |

场景 9 的证据包括 63 条安全规则告警以及 18 个具有强命令通道上下文的重复脚本 POST 端点。场景 10、11 均聚合出 USER、NICK、JOIN、PRIVMSG、PING、PONG 等 IRC 命令序列。

## 5. 标签启封与一致性

机器输出锁定后生成的 BinetFlow final-blind 标签汇总包含 3,504,550 条流：

- Background：3,156,515；
- Normal：48,532；
- Botnet：299,503。

分场景统计：

| 场景 | 总流数 | Botnet | Normal | Background |
| ---: | ---: | ---: | ---: | ---: |
| 9 | 2,087,508 | 184,987 | 29,967 | 1,872,554 |
| 10 | 1,309,791 | 106,352 | 15,847 | 1,187,592 |
| 11 | 107,251 | 8,164 | 2,718 | 96,369 |

三个场景均确认含 Botnet 活动，机器结果也均为明确安全分类。公开场景说明进一步表明：

- 场景 10 是 Rbot 通过 IRC 控制并执行 UDP/ICMP Flood，IRC C2 分类与说明一致，但事件主分类没有表达 Flood 动作；
- 场景 11 是 IRC Botnet 执行 ICMP DoS，IRC C2 分类与说明一致，但事件主分类没有表达 ICMP DoS；
- 场景 9 确认是 Neris 感染，机器发现强 HTTP 命令通道/外传候选行为，但现有粗标签不足以证明该细分类完全正确。

CTU-13 公开 PCAP 只包含 Botnet 流量，BinetFlow 则来自未公开的完整混合 PCAP，包含 Background、Normal 和 Botnet。两者无法逐流直接对齐，所以不能用 3,504,550 条标签计算当前 PCAP 检测的逐流混淆矩阵。

## 6. 冻结与哈希

候选冻结目录：

/home/user/jhk/security-datasets/registry/v12.1.1-streaming-candidate-freeze-20260825

- 流水线 SHA-256：8b8db779c3fd8ada186cb028dddf893cb7acbe16826b2cb5179cc58eb6ae0721
- 规则 SHA-256：21a4711aabb5358c325ff52f1aaacf453a8d8fca38ebfaf05a9bbceb1cab72f8
- 等价性摘要 SHA-256：e0f6c42dd2f6310560b9842ccd4c252a5341c88a8358cbb7496f8a352e69d2be

机器输出锁定目录：

/home/user/jhk/security-datasets/registry/v12.1.1-final-blind-machine-output-20260825

- 事件 SHA-256：e33dfdfc343754cdb18a1b82ce003e23aebf47fe6c02757853608ec1311f1bde
- 清单 SHA-256：2bc42d25fe13aa8ccfe142254294c319056b7670aa7c4ae0b874fa72e76112b5
- 完整引擎哈希清单 SHA-256：e5857b6d57a3f2951367d6ddaca9d7ae85f1b6c7924b83012e0380fa959d53fc
- 原始引擎文件：56 个
- 结果目录总大小：108,088,926,897 字节

标签与评估锁定目录：

/home/user/jhk/security-datasets/registry/v12.1.1-final-blind-evaluation-20260825

- 标签 SHA-256：48cb1716ef19dd58e014be254bde287c86384d3bfbb91eb4a09bbaa39da3aacb
- 评估摘要 SHA-256：68554a2c1a0558aba2ce521d88395f7c183b028f6a6240b501be13a7af0cbade

## 7. 结论边界与下一阶段

本轮可以表述为：冻结候选对三个独立保留 Botnet 场景实现 3/3 双引擎成功和 3/3 场景级明确安全分类，两个 Rbot 场景的 IRC C2 行为与公开说明一致。

不能表述为：逐流准确率 100%、召回率 100%、误报率 0，或已经达到生产 XDR 水平。

CTU-13 final-blind 已消耗，后续不得用这三个场景调整 v12.1.1 后再宣称独立盲测。下一阶段应升级为 v13：

1. 只用新的 development 语料补充 UDP Flood、ICMP Flood/DoS 等动作级检测；
2. 将单一主分类扩展为“C2 通道 + 攻击动作”的多发现结构；
3. 使用包含正常与恶意流量且能逐流对齐的新公开数据集建立真正的混淆矩阵；
4. 在新的独立保留集上再次执行“先锁定机器输出、后启封标签”的验收。
