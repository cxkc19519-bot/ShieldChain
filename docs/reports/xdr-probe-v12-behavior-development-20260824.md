# XDR/探针 v12 行为检测 development 报告

日期：2026-08-24

## 1. 目标

v12 针对 CTU-13 development 暴露的漏检与误归问题，引入场景无关的 Zeek 连接行为聚合，同时保持 v11 Suricata 规则不变。检测逻辑不读取 CTU 场景编号、恶意家族名、文件名标签或固定 IP。

## 2. 新增行为能力

- 聚合 IRC USER、NICK、JOIN、PRIVMSG、PING、PONG 命令序列，输出会话级命令控制证据；
- 识别高拒绝率、多目的地址连接扇出；
- 在异常活跃源中识别稳定周期连接，形成周期信标证据；
- 识别高目的地址、高目的端口占比的 UDP/P2P 行为；
- WebShell 重复 POST 增加缺失 User-Agent、命令型端点或大请求体等强上下文；
- 反弹连接只接受双向有载荷的长时 TCP 连接，UDP 5555 不再单独触发。

## 3. 验证方法

v12 只改变双引擎输出之后的分类逻辑，Suricata 规则和镜像没有变化。因此本轮直接把 v12 分类器应用于冻结的 v11 Zeek/Suricata 原始输出，避免重复运行同一 PCAP；这等价于在相同引擎输出上重新执行分类阶段，但不是一次新的双引擎完整运行。

- 正常 development：180 条隔离实验室 PCAP；
- CTU-13 development：场景 1、3、5、6、7、8、12 的 7 个 Botnet-only PCAP；
- validation 与 final-blind 均未运行、未读取标签；
- 本地单元与元数据回归：32/32 通过。

## 4. 结果

### 4.1 正常流量

180/180 条均为“网络行为待研判”，安全分类为 0。这个结果只约束当前自建正常流量，不能外推为生产误报率为零。

### 4.2 CTU-13 development

| 场景 | v11 | v12 |
| ---: | --- | --- |
| 1 Neris | 网络行为待研判 | 疑似扫描与僵尸网络传播 |
| 3 Rbot | Suricata 安全规则告警 | 疑似 IRC 命令控制 |
| 5 Fast-flux | 疑似 WebShell 交互 | 疑似扫描与僵尸网络传播 |
| 6 Donbot | 网络行为待研判 | 疑似周期信标与僵尸网络活动 |
| 7 Sogou | Suricata 安全规则告警 | Suricata 安全规则告警 |
| 8 Qvod | 网络行为待研判 | 疑似周期信标与僵尸网络活动 |
| 12 Botnet/P2P | 疑似反弹连接 | 疑似 P2P/UDP 僵尸网络 |

明确分类覆盖由 4/7 提升到 7/7；原 WebShell 与 UDP 反弹连接误归已消除。这里的 7/7 是 development 上的分类覆盖，不是准确率，也不能代替独立 validation。

## 5. 边界与后续门槛

- Fast-flux 当前依据异常连接扇出归为扫描与传播，尚未实现可靠的 DNS fast-flux 多证据分类；
- Sogou 仍只有通用 Suricata 告警，缺少更具体的行为语义；
- 阈值来自 development 与自建正常流量，仍需 validation 检查泛化；
- v11 已使用过的 final-blind 不能重新包装成 v12 未见盲集；v12 必须使用新的独立保留集。

## 6. 冻结产物

- 目录：`/home/user/jhk/security-datasets/registry/v12-candidate-freeze-20260824`
- 流水线 SHA-256：`9eee3c9e845c4bc6e50dcf06800d41a82d26389975aec82707a1777dca97a7f9`
- 规则 SHA-256：`21a4711aabb5358c325ff52f1aaacf453a8d8fca38ebfaf05a9bbceb1cab72f8`
- 正常结果 SHA-256：`6697fdf0800277a3be90ddbc5e6f4227a5420c05f4ca481bb5a77bd8c495b259`
- CTU 结果 SHA-256：`aae86061e6832b2cd2d64945b5e7d85ea6b96d59f5feb5746b1eeede64c76267`
- Suricata 镜像：`sha256:11269002d0a4ba2628aced92de6e8d04895c0efa4f1318804addcdc7ec76dbf6`
- Zeek 镜像：`sha256:adf96607966a0ee61800ede343c8c1cfe744bbb0a6e9b600cdc4ffa997e0fda0`

## 8. validation 后续

2026-08-25，冻结 v12 在 CTU-13 validation 上完成首次运行并在启封标签前锁定机器输出。validation 暴露出 Fast-flux-2 被过度归为 WebShell，随后形成 v12.1。v12.1 已使用 validation 调整，因此后续独立成绩必须来自仍未运行的新保留集。完整结果见 [v12 validation 验收报告](xdr-probe-v12-validation-20260825.md)。
