# XDR/探针 v12 validation 验收报告

日期：2026-08-25

## 1. 验收纪律

本次只运行 CTU-13 validation 场景 2、4、13。运行前确认 v12 候选代码、规则和 development 结果哈希未变化，validation 与 development、final-blind 的场景交集均为 0，三个 PCAP 的大小与 SHA-256 均与清单一致。

检测时未读取 validation BinetFlow 标签。三条机器输出完成后，先复制事件、清单、日志、输入清单和完整引擎文件哈希到只读目录，再生成 validation 标签报告。CTU-13 final-blind 场景 9、10、11 未运行，标签未生成。

## 2. 冻结 v12 首次 validation 输出

三个 PCAP 的 Suricata 与 Zeek 退出码均为 0：

| 场景 | v12 首次分类 | 安全告警 |
| ---: | --- | ---: |
| 2 Neris | 疑似扫描与僵尸网络传播 | 3 |
| 4 Rbot-DDoS | 疑似 IRC 命令控制 | 57 |
| 13 Fast-flux-2 | 疑似 WebShell 交互 | 1 |

机器输出目录：`/home/user/jhk/security-datasets/results/ctu-13-v12-validation/run-20260825-001902`。

锁定目录：`/home/user/jhk/security-datasets/registry/v12-validation-machine-output-20260825`。

- 事件 SHA-256：`6ca85a71c19c3793b3d4a42d3c9ea3f7d09a8fbc3b7bfd300ff658bdb5e30bbc`
- 清单 SHA-256：`2344d2d761e51f6d81d528cb12ed3641ea333b18080f50990ff54e1d9be8534f`
- 完整引擎哈希清单 SHA-256：`e1a0778a234b50d85c1ab3d80400387cacc34effee60c17b8a4a89460ebc4a9a`

## 3. validation 标签

锁定机器输出后生成的 BinetFlow validation 标签报告包含 4,854,347 条流：

- Background：4,724,496；
- Normal：66,327；
- Botnet：63,524。

标签报告 SHA-256：`410a005adbcddf855696cf14e1b6754b77ac11ca83d44002d76d669efcb66e1d`。

BinetFlow 是完整混合场景，公开 PCAP 是 Botnet-only 抽取，两者不能直接逐流对齐。本报告只使用标签确认三个 validation 场景确实包含 Botnet 活动，不把 BinetFlow 总行数当作 PCAP 检测样本数。

## 4. validation 暴露的问题与 v12.1

Fast-flux-2 中，主机向陌生域名的 `/ajax.php` 连续 POST 50 次，缺失 User-Agent，最大请求体约 106 KB，并触发“大 HTTP POST”规则。这是强异常证据，但仅凭通用 PHP 端点和大请求体不足以断言 WebShell。

v12.1 因此把非命令型端点上的大体积/重复脚本 POST 归为“疑似 HTTP 命令控制或数据外传”；只有明确命令型端点或 WebShell 特征才继续归为 WebShell。实现没有写入场景编号、家族名、文件名或固定 IP。

v12.1 回归结果：

- 自建正常 development：0/180 安全分类；
- CTU-13 development：7/7 明确分类，结果无退化；
- CTU-13 validation：3/3 明确分类；
- 本地脚本测试：43/43 通过。

v12.1 的 validation 结果属于使用 validation 调整后的结果，不是独立泛化成绩。独立验收必须使用仍未运行的新保留集。

## 5. v12.1 validation 分类

| 场景 | v12.1 分类 |
| ---: | --- |
| 2 Neris | 疑似扫描与僵尸网络传播 |
| 4 Rbot-DDoS | 疑似 IRC 命令控制 |
| 13 Fast-flux-2 | 疑似 HTTP 命令控制或数据外传 |

这里的 3/3 是明确分类覆盖，不是准确率。标签只提供 Botnet/Normal/Background 等粗粒度真值，不能证明细分类别完全正确。

## 6. 冻结产物

v12.1 冻结目录：`/home/user/jhk/security-datasets/registry/v12.1-validation-candidate-freeze-20260825`。

- 流水线 SHA-256：`d53177d260717f0a984f6ca0ec07eb9cbbe98889f3b0a3c47ab7552dbf5ee369`
- 规则 SHA-256：`21a4711aabb5358c325ff52f1aaacf453a8d8fca38ebfaf05a9bbceb1cab72f8`
- 正常 development 结果：`7bd79c4813d2d7c0b2c89807de1adf6ff54d05110c9d4eee7d0f70d6f87fbbaa`
- CTU development 结果：`5a3b7bb1ba766a0bdebe152db22eef4875b76931d5c3e01a462fe3e7935ccd46`
- CTU validation 结果：`b32eb9a08562f8a2cda9d89d7cb85aac6aec96beb5720c23225905c8aaddc886`
- Suricata 镜像：`sha256:11269002d0a4ba2628aced92de6e8d04895c0efa4f1318804addcdc7ec76dbf6`
- Zeek 镜像：`sha256:adf96607966a0ee61800ede343c8c1cfe744bbb0a6e9b600cdc4ffa997e0fda0`

## 7. 下一门槛

final-blind 在以下条件全部满足前不得运行：

1. v12.1 代码、规则、镜像、清单和评价口径保持冻结；
2. 明确 final-blind 只运行一次，输出先锁定再启封标签；
3. 预留足够运行时间与磁盘，场景 10 PCAP 约 70.7 GB；
4. 把结果表述为检测覆盖和粗标签一致性，不包装成生产准确率。
## 8. 后续状态

本报告记录的是 validation 当时的状态。2026-08-25 后续已完成 v12.1.1 流式性能修订、190 个冻结样本等价回归以及 CTU-13 场景 9、10、11 的一次性 final-blind 验收。机器输出和 56 个引擎文件哈希在标签启封前锁定；完整结果见 [v12.1.1 final-blind 验收报告](xdr-probe-v1211-final-blind-20260825.md)。
