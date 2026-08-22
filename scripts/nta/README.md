# NTA 离线检测工具

该目录提供 ShieldChain 的离线 PCAP 检测链路。它使用 Docker 分别运行
Suricata 与 Zeek，生成结构化检测事件，不会把 PCAP 回放到真实网络，也不会
根据文件名推断攻击类型。

## 文件

- `nta_offline_pipeline.py`：离线运行 Suricata/Zeek 并生成 `events.jsonl`。
- `ingest_nta_events.py`：将事件提交到 ShieldChain 的 Wazuh 兼容接入接口。
- `generate_benign_fixture.py`：只在文件中生成 RFC1918 正常 HTTP PCAP，不发送网络流量，用于误报回归。
- `../../config/suricata/shieldchain-nta.rules`：ShieldChain 自定义告警规则。

当前 v6 规则集包含 54 条 ShieldChain 自定义 Suricata 规则定义（其中 1 条为 `flowbits:noalert` 关联状态规则），并结合 Zeek 元数据行为检测。规则覆盖 WebShell、reDuh 隧道、PowerShell/Unix 命令执行、可疑反弹连接、SQL 注入等场景。v6 将高熵 `fish=` 从单请求告警改为请求/响应关联检测，并删除会误报正常报表下载的单次大响应判断。详细验收结果见 [v6 规则评估报告](../../docs/reports/xdr-probe-rule-evaluation-v6-20260822.md)。

## 数据集划分与验收

比赛方提供的是一个整体 PCAP 语料，仓库所述 development（701）、validation（701）和 final-blind（935）是 ShieldChain 为避免规则过拟合而创建的工程划分，不是比赛方官方划分，也不是在训练模型。完整说明、服务器路径、冻结规则哈希和同门复现流程见 [NTA 数据集划分与独立验收](../../docs/operations/nta-dataset-split-and-evaluation.md)。

## 前置条件

- Python 3.10+
- Docker
- 可用镜像：`jasonish/suricata:7.0.16`、`zeek/zeek:latest`
- 只对已获授权的数据集进行分析

## 数据目录

默认数据根目录是仓库下的 `data/nta`，可通过环境变量覆盖：

- `SHIELDCHAIN_NTA_ROOT`：数据根目录
- `SHIELDCHAIN_NTA_ARCHIVE`：可选 ZIP 数据集路径
- `SHIELDCHAIN_NTA_PCAP_ROOT`：PCAP 目录
- `SHIELDCHAIN_NTA_RESULT_ROOT`：结果目录
- `SHIELDCHAIN_SURICATA_RULES`：自定义规则文件
- `SHIELDCHAIN_SURICATA_IMAGE`、`SHIELDCHAIN_ZEEK_IMAGE`：镜像名称

Linux 示例：

```bash
export SHIELDCHAIN_NTA_ROOT=/path/to/nta-data
export SHIELDCHAIN_NTA_PCAP_ROOT=/path/to/nta-data/pcap
python3 scripts/nta/nta_offline_pipeline.py --limit 12
```

使用固定匿名样本清单时，会完整处理清单中的所有项目：

```bash
python3 scripts/nta/nta_offline_pipeline.py \
  --sample-list /path/to/validation-sample.txt
```

处理整个目录：

```bash
python3 scripts/nta/nta_offline_pipeline.py --all
```

生成不联网的正常业务回归 PCAP：

```bash
python3 scripts/nta/generate_benign_fixture.py /tmp/benign-business.pcap
```

该 PCAP 包含正常大报表响应、普通 `fish=` 表单参数和登录请求，只用于检查候选规则是否把常见业务流量误判为 WebShell。它是合成护栏，不代表真实生产流量分布。

每次运行会在结果目录生成独立的 `run-YYYYMMDD-HHMMSS` 目录，包括：

- `events.jsonl`：可导入 ShieldChain 的最小化事件
- `manifest.json`：规则哈希、样本数量和分类统计
- 每个样本的 Zeek/Suricata 日志与引擎输出

## 导入 ShieldChain

先配置接入令牌和接口地址：

```bash
export WAZUH_WEBHOOK_TOKEN=replace-with-local-token
export SHIELDCHAIN_NTA_INGEST_ENDPOINT=http://127.0.0.1:8000/api/v1/integrations/wazuh/alerts
python3 scripts/nta/ingest_nta_events.py /path/to/run/events.jsonl
```

运行不需要 Docker 的分类单元测试：

```bash
python3 -m unittest tests/scripts/test_nta_offline_pipeline.py
```

不要把令牌、原始 PCAP、标签映射或含敏感信息的日志提交到 Git。

## 安全边界

- 分析容器使用 `--network none`、只读根文件系统和最小权限。
- 离线 PCAP 使用 `-k none` 忽略采集文件中的校验和卸载伪差；实时检测不应照搬此参数。
- 自定义规则只产生告警，不自动阻断或执行处置。
- 没有经过确认的正常流量集时，只能报告检测覆盖率，不能宣称准确率或误报率。
