# NTA 数据集划分与独立验收

本文说明 ShieldChain 如何使用比赛方提供的 NTA PCAP 数据集开发和验收开源探针/XDR 替代链路。

## 1. 数据来源与划分性质

比赛方提供的是一个整体 PCAP 样本集合，并未随材料提供“训练集、验证集、测试集”的官方划分。项目为了避免一边看标签调规则、一边又用同一批样本宣称效果，按固定、可复现的方法自行划分为：

| 子集 | 数量 | 用途 |
| --- | ---: | --- |
| development | 701 | 查看标签、编写和调试 Suricata/Zeek 规则 |
| validation | 701 | 冻结规则后做独立回归，禁止继续针对该次结果调参 |
| final-blind | 935 | 最终盲测，当前保持封存 |
| 合计 | 2337 | 比赛方 NTA PCAP 总量 |

这不是模型训练，也不能称作比赛方官方训练/测试集。这里的“development / validation / final-blind”只是规则工程中的职责隔离：开发集用于写规则，验证集用于检查泛化，最终盲测集用于最后一次验收。

## 2. 服务器目录

仅在 `/home/user/jhk` 范围内操作：

- 原始数据：`/home/user/jhk/nta-dataset`
- 匿名副本：`/home/user/jhk/nta-dataset-blind`
- 匿名 PCAP：`/home/user/jhk/nta-dataset-blind/pcap`
- 固定清单与评估材料：`/home/user/jhk/nta-dataset-blind/evaluation`
- 检测结果：`/home/user/jhk/nta-dataset-blind/results`
- 标签映射：`/home/user/jhk/nta-dataset-blind-ground-truth.csv`

标签映射权限应保持为 `600`，不得提交到 GitHub，也不得作为检测器输入。匿名 PCAP 文件名本身不包含攻击标签。

## 3. 为什么不是训练模型也要划分

Suricata 签名、Zeek 行为阈值和分类逻辑同样会产生“过拟合”。如果规则作者先查看所有文件名或标签，再在同一批数据上统计命中率，结果只表示规则记住了已知样本，无法说明面对新流量是否有效。

因此规则验收遵循以下顺序：

1. 只在 development 中分析样本和调整规则。
2. 冻结规则文件与流水线，并记录 SHA-256。
3. 在从未参与调参的 validation 样本上运行。
4. 先锁定机器输出，再按受控标签映射做人工审计。
5. final-blind 在规则方案稳定前不运行。

## 4. 当前冻结版本

v3 冻结文件位于运行目录：

- `rules/shieldchain-nta.rules.v3-frozen`
- `tools/nta_offline_pipeline.py.v3-frozen`

对应 SHA-256：

- 规则：`d71451d06a584d1752a55cc6c74bf8cac5e7954d8e876109d5b08d3ce183e2d5`
- 流水线：`8195899b92c35d14e3e7e43a848290b7b50939202c25aa7fea4cf83ac361b37c`

v3 开发回归使用 23 个 development 样本；独立验证使用第三批、且未出现在旧验证清单中的 24 个 validation 样本。详细数字见 `docs/reports/xdr-probe-rule-evaluation-v3-20260821.md`。

## 5. 同门复现实验

进入项目并配置数据目录：

```bash
cd /home/user/jhk/shieldchain
export SHIELDCHAIN_NTA_ROOT=/home/user/jhk/nta-dataset-blind
export SHIELDCHAIN_NTA_PCAP_ROOT=/home/user/jhk/nta-dataset-blind/pcap
export SHIELDCHAIN_NTA_RESULT_ROOT=/home/user/jhk/nta-dataset-blind/results
export SHIELDCHAIN_SURICATA_RULES="$PWD/config/suricata/shieldchain-nta.rules"
```

先检查脚本和规则：

```bash
python3 -m py_compile scripts/nta/nta_offline_pipeline.py scripts/nta/ingest_nta_events.py
docker run --rm --network none \
  -v "$PWD/config/suricata:/rules:ro" \
  jasonish/suricata:7.0.16 \
  suricata -T -c /etc/suricata/suricata.yaml -S /rules/shieldchain-nta.rules
```

使用固定清单运行（清单路径按本次实验选择）：

```bash
python3 scripts/nta/nta_offline_pipeline.py \
  --sample-list /home/user/jhk/nta-dataset-blind/evaluation/validation-sample-v3-24.txt
```

运行结果写入新的 `run-YYYYMMDD-HHMMSS` 目录。先保存 `manifest.json`、`events.jsonl`、规则哈希和运行时间，再进行标签审计；不要边看验证标签边改规则。

## 6. 结果应该怎样解释

当前数据集没有经过确认的正常流量对照集，因此只能报告：

- 命中样本数、告警数和规则覆盖；
- 待研判样本比例；
- 标签审计后的攻击家族覆盖；
- 明显错分或漏检案例。

不能据此宣称“准确率高”“误报率低”或“达到生产级 XDR”。要计算精确率、召回率和误报率，还需要来源可信、代表真实业务分布的正常流量与逐样本真值。

## 7. 安全与数据边界

- PCAP 只在隔离容器中离线解析，容器使用 `--network none`。
- 不回放到校园网或生产网络。
- 不提交原始 PCAP、标签映射、访问令牌和含敏感载荷的完整日志。
- 规则只产生告警，不自动阻断。
- final-blind 只有在候选规则冻结、评估方案写定后才能启封。
