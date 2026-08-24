# CTU-13 v11 外部 development 基线报告

日期：2026-08-24

## 1. 目的

本次实验使用从比赛方数据上冻结的 v11 Suricata 规则与离线流水线，直接分析此前未用于 v11 开发的 CTU-13 公开 Botnet-only PCAP。目标是测量旧规则对外部僵尸网络流量的迁移覆盖，并识别 v12 的开发方向；不是训练模型，也不回改 v11。

## 2. 数据与隔离

CTU-13 以完整场景划分，development 使用场景 1、3、5、6、7、8、12。对应 7 个公开 PCAP 都只包含 Botnet 流量；完整混合流量只以 BinetFlow 形式公开。

BinetFlow development 标签共 11,617,803 条：Background 11,294,557、Normal 241,574、Botnet 81,672。validation 场景 2、4、13 和 final-blind 场景 9、10、11 的标签报告未生成。

CTU-13 本身是公开数据，因此项目中的 `final-blind` 仅代表标签隔离流程，不是未知私有测试集。

## 3. 冻结输入

- v11 规则 SHA-256：`21a4711aabb5358c325ff52f1aaacf453a8d8fca38ebfaf05a9bbceb1cab72f8`
- v11 流水线 SHA-256：`fffd10d94d432a967adc685dbdd7e3e91a2de724fda01ab5dc68c7537eff0cb7`
- development PCAP 清单 SHA-256：`4bad60bd429148278304cb86fbda9e93695499ef3909fe1a2abd2c7ddb68d087`
- development 场景 JSON SHA-256：`dd8d327705e6faeb00ce2b3faec759dff9b4183c2697add91dc3ad2b10eab8b7`
- development 标签报告 SHA-256：`55ba7cc6aa681150103b7ffbd9c1eb12cb29646bd93424cccccac1065ca8dd75`
- Suricata 镜像：`sha256:11269002d0a4ba2628aced92de6e8d04895c0efa4f1318804addcdc7ec76dbf6`
- Zeek 镜像：`sha256:adf96607966a0ee61800ede343c8c1cfe744bbb0a6e9b600cdc4ffa997e0fda0`

两个分析容器都使用 `--network none`，只离线读取只读 PCAP，没有回放流量。

## 4. 结果

| 场景 | 公开 PCAP | v11 分类 | Suricata 安全告警 |
| ---: | --- | --- | ---: |
| 1 | Neris | 网络行为待研判 | 0 |
| 3 | Rbot | Suricata 安全规则告警 | 3,393 |
| 5 | Fast-flux | 疑似 WebShell 交互 | 0 |
| 6 | Donbot | 网络行为待研判 | 0 |
| 7 | Sogou | Suricata 安全规则告警 | 1 |
| 8 | Qvod | 网络行为待研判 | 0 |
| 12 | Botnet/P2P | 疑似反弹连接 | 0 |

聚合结果：

- 双引擎成功：7/7；
- 产生明确类别的样本：4/7（57.14%）；
- Suricata 安全告警样本：2/7（28.57%）；
- 网络行为待研判：3/7（42.86%）；
- Suricata 安全告警：3,394 条；
- Suricata 原始告警/解码事件：22,523 条。

Rbot 的安全告警主要为 `ET CHAT IRC PONG response` 3,334 条、IRC PRIVMSG 28 条、IRC PING 19 条，其余为少量 USER/NICK/JOIN/check-in 规则。Sogou 的一条安全告警来自 ShieldChain 的 HTTP URI 空字节规则。

## 5. 解释与问题

这些数字不是恶意流量分类准确率：

- Fast-flux 因重复 HTTP 脚本端点触发 Zeek WebShell 启发式，被归为“疑似 WebShell”，与官方场景语义不一致；
- 场景 12 因端口 5555 长连接被归为“疑似反弹连接”，只能视为待核实行为线索；
- Neris、Donbot、Qvod 没有安全告警，说明 v11 缺少周期信标、DNS/fast-flux、P2P、邮件僵尸网络和 C2 序列检测；
- Rbot 的大量告警主要来自通用 IRC 协议规则，数量大不等于 3,393 个独立攻击事件；
- Botnet-only PCAP 没有正常流量对照，不能计算误报率、精确率或生产可用性。

## 6. v12 开发方向

v12 只能使用 development 进行开发，建议按以下顺序补强：

1. 将 IRC PING/PONG/PRIVMSG 聚合为会话级 C2 证据，避免按包重复告警；
2. 增加周期连接、低字节长时连接、目的地址扇出和端口扫描等 Zeek 行为特征；
3. 增加 DNS 快速变换、域名/IP 高变动率和短 TTL 组合检测；
4. 为 P2P/UDP 扫描和流量洪泛增加场景无关的统计特征；
5. 把“WebShell”“反弹连接”等单一启发式降为候选证据，交由多证据关联后再定类；
6. 冻结 v12 后运行 validation，先锁定机器输出，再生成 validation 标签报告；
7. final-blind 只在 validation 通过后一次性运行。

## 7. 锁定产物

- 运行目录：`/home/user/jhk/security-datasets/results/ctu-13-v11-development/run-20260824-232758`
- 事件 SHA-256：`e78ee11b7332cd8539044410cd6303063eda7c205621c7624e55dbda3062876f`
- 运行清单 SHA-256：`9ed56cd2f0a63b7100b222b3e593f63940981ff5bae1aa7b4886b88178e1af5b`
- 锁定摘要：`/home/user/jhk/security-datasets/registry/ctu-13-v11-development-baseline.json`
- 锁定摘要 SHA-256：`2cc23415b9923735ca8e51a31f008ae6888aae5579a2f905dff01fe2e98365f3`
