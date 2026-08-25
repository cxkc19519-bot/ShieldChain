# 公开安全数据集接入与 CTU-13 操作说明

本文说明 ShieldChain 如何在学校服务器安全接入公开网络安全数据集。公开数据不放进项目仓库，也不能因为“公开”就跳过来源、许可证、完整性和恶意载荷检查。

## 1. 服务器目录

所有数据只存放在 `/home/user/jhk/security-datasets`：

```text
security-datasets/
├── downloads/    # 原始只读归档和 SHA-256
├── extracted/    # 白名单提取结果
├── normalized/   # 统一后的 PCAP/流标签
├── splits/       # development/validation/final-blind 清单
├── labels/       # 受限标签映射，权限 700
├── results/      # Zeek/Suricata 输出
├── registry/     # 来源、许可证、大小、哈希和处理记录
└── logs/         # 下载与准备日志
```

`downloads`、`extracted`、`labels` 和 `results` 都不得提交 GitHub。仓库只保存工具、聚合指标和不含敏感载荷的说明。

## 2. 第一批数据：CTU-13

官方来源：

- 项目页：`https://www.stratosphereips.org/datasets-ctu13`
- 官方归档：`https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2`
- 下载大小：1,997,547,391 字节
- 本次 SHA-256：`1f8daeca146131a368b432b2d8625de5e4429bce833f3e4cf4bea8312344ab7f`

CTU-13 包含 13 个 Botnet 场景，适合补充 ShieldChain 当前较弱的 C2、周期连接、恶意软件下载和僵尸网络检测。它同时可能包含原始恶意样本，不能直接全量解压，更不能执行其中任何载荷。

截至 2026-08-24，服务器已完成归档检查和白名单提取：共发现 66 个成员，实际提取 39 个文件（13 个 PCAP、13 个 BinetFlow 和 13 个说明文件），合计 79,738,362,429 字节；另有 13 个 `.exe` 恶意样本被明确排除，提取目录内 `.exe` 数为 0。检查记录位于 `/home/user/jhk/security-datasets/registry/ctu-13-inspection.json`，提取报告位于 `/home/user/jhk/security-datasets/registry/ctu-13-extraction.json`，报告与目录内清单的 SHA-256 均为 `8ca9cc5aac01ed5b0dbb856ebf6eb848deb9722744df412e7a66d4bd827c8681`。

## 3. 下载与校验

服务器采用可续传下载，归档固定保存为：

```text
/home/user/jhk/security-datasets/downloads/CTU-13-Dataset.tar.bz2
```

校验命令必须在下载目录运行，确保 SHA 文件中的相对文件名能够解析：

```bash
cd /home/user/jhk/security-datasets/downloads
sha256sum -c CTU-13-Dataset.tar.bz2.sha256
bzip2 -t CTU-13-Dataset.tar.bz2
```

只有精确字节数、SHA-256 和 bzip2 完整性全部通过，归档才可进入下一步。

## 4. 安全检查与白名单提取

项目提供 `scripts/nta/prepare_ctu13.py`。默认只检查归档，不提取文件：

```bash
cd /home/user/jhk/shieldchain
python3 scripts/nta/prepare_ctu13.py \
  /home/user/jhk/security-datasets/downloads/CTU-13-Dataset.tar.bz2 \
  --expected-sha256 1f8daeca146131a368b432b2d8625de5e4429bce833f3e4cf4bea8312344ab7f \
  --report /home/user/jhk/security-datasets/registry/ctu-13-inspection.json
```

检查通过后才允许显式提取：

```bash
python3 scripts/nta/prepare_ctu13.py \
  /home/user/jhk/security-datasets/downloads/CTU-13-Dataset.tar.bz2 \
  --expected-sha256 1f8daeca146131a368b432b2d8625de5e4429bce833f3e4cf4bea8312344ab7f \
  --extract-to /home/user/jhk/security-datasets/extracted/ctu-13 \
  --report /home/user/jhk/security-datasets/registry/ctu-13-extraction.json
```

工具的保护措施：

- 拒绝绝对路径、`..` 路径穿越和重复路径；
- 拒绝符号链接、硬链接和设备文件；
- 限制归档成员数量和白名单文件展开总量；
- 只提取 PCAP、Argus/BinetFlow 标签、CSV 和说明文件；
- 跳过 `.exe` 等载荷和未知后缀；
- 输出目录必须不存在，避免覆盖已有数据；
- 为每个提取文件生成大小和 SHA-256 清单；
- 提取文件默认只读。

不要使用 `tar -xjf` 绕过这些检查。

## 5. 场景划分与标签适配

`scripts/nta/prepare_ctu13_splits.py` 会核对 13 个场景的 PCAP、BinetFlow、README 和提取清单哈希，并以完整场景为最小单元生成 v1 清单：

| 子集 | 场景 | 用途 |
| --- | --- | --- |
| development | 1、3、5、6、7、8、12 | 可读取标签，用于外部基线分析和后续 v12 开发 |
| validation | 2、4、13 | v12 已完成首次独立验证，机器输出锁定后已生成标签 |
| final-blind | 9、10、11 | v12.1.1 已完成一次性验收，禁止再作为独立盲集调参 |

服务器产物：

- 清单：`/home/user/jhk/security-datasets/splits/ctu-13-v1`；
- 受限标签：`/home/user/jhk/security-datasets/labels/ctu-13-v1`；
- 每个子集同时生成 JSON 场景清单和可直接传给 `nta_offline_pipeline.py --sample-list` 的 PCAP 文本清单；
- validation 与 final-blind 标签报告均已在对应机器输出只读锁定后生成。

development 已适配 11,617,803 条 BinetFlow：Background 11,294,557、Normal 241,574、Botnet 81,672。validation 已适配 4,854,347 条，final-blind 已适配 3,504,550 条；二者均在机器输出锁定后才启封。适配器保留原始标签，同时归一为 `background`、`normal`、`botnet`、`unknown` 四类；支持十进制、十六进制和 Argus 命名端口，并拒绝未知表头或畸形行。

CTU-13 是公开数据，场景和标签可从公开资料获取，因此这里的 `final-blind` 仅表示 ShieldChain 工程流程中的标签隔离保留集，不是未知私有测试集，也不能据此宣称竞赛级盲测成绩。

冻结 v11 已完成 7 个 development Botnet-only PCAP 外部基线：双引擎成功 7/7，明确产生某类发现 4/7，Suricata 安全告警样本 2/7，待研判 3/7。结果暴露出 IRC 告警重复、Fast-flux 被误归为 WebShell、单端口启发式过强以及 Neris/Donbot/Qvod 缺少安全告警等问题。完整证据、哈希和 v12 方向见 [CTU-13 v11 外部 development 基线报告](../reports/ctu13-v11-external-development-baseline-20260824.md)。

## 6. 划分与评测原则

CTU-13 不能随机按数据包或同一场景中的流拆分到不同集合，否则相同感染主机、地址和行为模式会泄漏到验证集。应按完整场景划分：

- development：只用于设计 v12 规则和行为特征；
- validation：冻结规则后检查跨场景泛化，不能看结果继续回改同一版本；
- final-blind：匿名清单、标签隔离，只运行一次。

CTU-13 的完整混合 PCAP 因隐私原因未公开；官方提供 Botnet PCAP 和带 Normal/Background/Botnet/C2 标签的双向流文件。因此需要分别报告：

- PCAP 上 Suricata/Zeek 的检测覆盖；
- 双向流标签上的 C2/Botnet 流级精确率、召回率和 F1；
- 引擎失败、解析失败和未关联标签数量；
- 不能从 Botnet-only PCAP 单独推导生产误报率。

## 7. 后续顺序

1. 完成 CTU-13 归档检查和白名单提取；
2. 编写 CTU-13 BinetFlow 标签适配器；
3. 按场景建立匿名 development/validation/final-blind 清单；
4. 先用冻结 v11 跑外部基线，不调规则；
5. 再基于 development 开发 v12；
6. 最后补充 CIC-IDS2017 正常/Web/SQL 流量，以及隔离 Windows + Wazuh + Atomic Red Team 主机行为。

历史 935 条比赛方 final-blind 已经消耗，不能用 CTU-13 调整规则后重新把它包装成未见测试集。

## CTU-13 v12 行为检测候选（2026-08-24）

v12 分类器只使用 CTU-13 development 和自建正常 development 开发，增加 IRC 序列聚合、异常连接扇出、周期信标与 UDP/P2P 行为。对冻结 Zeek/Suricata 输出重新分类后，CTU development 明确分类覆盖由 4/7 提升到 7/7，正常 development 安全分类保持 0/180。

该结果不是准确率，不能证明生产流量可用，也不代表可以启封 validation 或把 v11 final-blind 重新当作盲集。证据和哈希见 [v12 行为检测 development 报告](../reports/xdr-probe-v12-behavior-development-20260824.md)。

## CTU-13 v12 validation 与 v12.1（2026-08-25）

冻结 v12 首次运行 validation 场景 2、4、13，3/3 双引擎成功，机器输出在标签启封前锁定。Fast-flux-2 的通用大 HTTP POST 被归为 WebShell，说明类别过于具体。v12.1 将非命令型脚本端点上的强异常 POST 改为“疑似 HTTP 命令控制或数据外传”，并在正常 development、CTU development 和 validation 上重新回归。

v12.1 使用过 validation 做类别修正，因此 validation 的 3/3 明确分类覆盖不能再作为独立泛化结果。完整纪律、证据和哈希见 [v12 validation 验收报告](../reports/xdr-probe-v12-validation-20260825.md)。

## CTU-13 v12.1.1 final-blind（2026-08-25）

v12.1.1 是 v12.1 的纯性能修订：Suricata JSONL 和 Zeek conn.log 改为流式读取，以处理场景 10 的 70.7 GB PCAP 所产生的超大日志。它在正常 development 180 条、CTU development 7 条和 validation 3 条冻结输出上完成 190/190 语义等价验证，检测规则未改变。

场景 9、10、11 只运行一次，3/3 双引擎成功；事件、清单、日志以及 56 个原始引擎文件哈希在标签启封前锁定。三场景均给出明确安全分类，公开 BinetFlow 标签也均含 Botnet 流。Rbot 场景的 IRC C2 分类与公开说明一致，但 UDP/ICMP Flood 动作没有进入主分类；Neris 的 HTTP 细分类只能视为候选结论。

公开 PCAP 是 Botnet-only，BinetFlow 是包含 Background、Normal、Botnet 的完整混合流量，二者无法逐流直接对齐。因此本轮只能报告 3/3 场景级恶意活动覆盖，不能报告逐流准确率或召回率。所有 PCAP 和约 108.09 GB 引擎结果均保存在服务器 /home/user/jhk/security-datasets，未下载到本机。详见 [v12.1.1 final-blind 验收报告](../reports/xdr-probe-v1211-final-blind-20260825.md)。

## CSE-CIC-IDS2018 v13 DDoS 行为验收

v13 使用加拿大网络安全研究院（CIC）官方 [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) 原始 PCAP，目标是在现有 C2 主分类之外独立输出拒绝服务动作，而不是根据文件名或场景说明猜测攻击。官方页面说明数据集含真实格式的 PCAP、正常背景流量和 DDoS 场景，并按攻击时间、来源、目标、端口和协议标注流量。

本轮在读取任何检测结果前固定以下角色：

- development：2018-02-20，LOIC-HTTP（10:12–11:17）和 LOIC-UDP（13:13–13:32），允许检查结果并调整通用阈值；
- independent holdout：2018-02-21，LOIC-UDP（10:09–10:43）和 HOIC（14:05–15:05），候选代码、阈值、测试与哈希冻结前禁止检查任何检测输出或包派生特征；
- benign holdout：从 2018-02-21 两个攻击窗口至少相隔 30 分钟的时间段按预先固定规则取样，和攻击切片一同只运行一次。

最初只把 CTU-13 场景 4 作为 development；实测其公开 Botnet-only PCAP 能看到 IRC C2，却没有保留洪泛动作包。因此在候选冻结前通过补充协议增加 2018-02-20 正样本开发集，2018-02-21 的留出角色保持不变。协议证据保存在服务器：

- `/home/user/jhk/security-datasets/registry/v13-protocol-frozen-20260825.json`，SHA-256 `4735e94ce9be273154c93db8739f7d89fd2323e240ef8a83fc911ec1e25fbf23`；
- `/home/user/jhk/security-datasets/registry/v13-protocol-addendum-1-20260825.json`，SHA-256 `150d1e831036ce7e99c3390015dc40dc0a34f63dc6127088e3bbf7ea522b9fea`。

原始包只保存在服务器 `/home/user/jhk/security-datasets/downloads/cse-cic-ids2018`，不会下载到本机或提交 Git。开发日官方对象约 44.4 GB，留出日官方对象约 53.5 GB。下载支持断点和分段长度校验，完整包另算 SHA-256；解压后使用 `scripts/nta/slice_pcap_time.py` 一次顺序扫描写出带绝对时区的窗口切片与清单。

检测特征明确禁止使用文件名、日期、场景编号、固定攻击者/目标 IP 和官方标签。v13 只使用 Zeek/Suricata 观测到的连接数、包速率、来源数量、目标集中度、端口分布、失败比例和 HTTP 请求速率；事件通过 `evidence.behavior_findings` 保存可组合发现。

开发日原始包的最后一条 PCAP 记录不完整。严格模式首先发现并拒绝该文件；确认损坏只在尾部后，使用显式 `--allow-truncated-tail` 重新切片，并在清单保留 `truncated_tail_discarded: true`。这不是静默修复。最终得到 3 个 HTTP 攻击窗口、3 个 UDP 攻击窗口和 3 个非攻击时间对照窗口，共约 1.43 GB；14:00 对照窗口为空，已从样本清单排除。

候选冻结前的开发结果如下：

- 3/3 HTTP 窗口输出“疑似 HTTP 请求洪泛拒绝服务”；
- 3/3 UDP 窗口输出“疑似 UDP/ICMP 洪泛拒绝服务”；
- 3/3 非攻击时间对照窗口没有产生洪泛行为发现；其中一个窗口命中公开威胁情报信誉 IP 规则，该规则告警与洪泛行为分开保留；
- 180 条隔离正常 development 再分类的洪泛行为命中为 0/180；
- 7 个 CTU-13 C2/P2P development 输出的洪泛行为命中为 0/7，原有 C2/P2P 分类未被新动作覆盖。

候选代码 SHA-256 为 `f69ecc97a62528308ed77b562385988ff720a1bc88f1a001d9c5c5e204da794e`，规则 SHA-256 为 `21a4711aabb5358c325ff52f1aaacf453a8d8fca38ebfaf05f8b96d39ba26f0af`。完整冻结清单保存在服务器 `/home/user/jhk/security-datasets/registry/v13-candidate-freeze-20260825`。上述结果只是开发验收和误报护栏，不是独立留出集成绩或生产误报率；2018-02-21 留出集只能在冻结后运行一次。

独立留出集已在冻结后一次性完成：3/3 LOIC-UDP 窗口输出 UDP/ICMP 洪泛，3/3 HOIC 窗口输出 HTTP 请求洪泛，2/2 非攻击时间对照窗口没有洪泛行为发现，双引擎失败为 0。预先固定的 `benign-1200` 窗口为空，未作为样本运行。详细的完整性处理、行为指标、结果哈希和限制见 [v13 独立留出集验收报告](../reports/xdr-probe-v13-cse-cic-ids2018-holdout-20260825.md)。
