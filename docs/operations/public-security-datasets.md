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

## 5. 划分与评测原则

CTU-13 不能随机按数据包或同一场景中的流拆分到不同集合，否则相同感染主机、地址和行为模式会泄漏到验证集。应按完整场景划分：

- development：只用于设计 v12 规则和行为特征；
- validation：冻结规则后检查跨场景泛化，不能看结果继续回改同一版本；
- final-blind：匿名清单、标签隔离，只运行一次。

CTU-13 的完整混合 PCAP 因隐私原因未公开；官方提供 Botnet PCAP 和带 Normal/Background/Botnet/C2 标签的双向流文件。因此需要分别报告：

- PCAP 上 Suricata/Zeek 的检测覆盖；
- 双向流标签上的 C2/Botnet 流级精确率、召回率和 F1；
- 引擎失败、解析失败和未关联标签数量；
- 不能从 Botnet-only PCAP 单独推导生产误报率。

## 6. 后续顺序

1. 完成 CTU-13 归档检查和白名单提取；
2. 编写 CTU-13 BinetFlow 标签适配器；
3. 按场景建立匿名 development/validation/final-blind 清单；
4. 先用冻结 v11 跑外部基线，不调规则；
5. 再基于 development 开发 v12；
6. 最后补充 CIC-IDS2017 正常/Web/SQL 流量，以及隔离 Windows + Wazuh + Atomic Red Team 主机行为。

历史 935 条比赛方 final-blind 已经消耗，不能用 CTU-13 调整规则后重新把它包装成未见测试集。
