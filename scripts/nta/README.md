# NTA 离线检测工具

该目录提供 ShieldChain 的离线 PCAP 检测链路。它使用 Docker 分别运行
Suricata 与 Zeek，生成结构化检测事件，不会把 PCAP 回放到真实网络，也不会
根据文件名推断攻击类型。

## 文件

- `nta_offline_pipeline.py`：离线运行 Suricata/Zeek 并生成 `events.jsonl`。
- `prepare_ctu13.py`：检查 CTU-13 归档并只提取 PCAP、流标签和说明文件，排除恶意载荷。
- `prepare_ctu13_splits.py`：适配 BinetFlow 标签，按完整场景生成 development/validation/final-blind 清单，默认只读取 development 标签。
- `ingest_nta_events.py`：将事件提交到 ShieldChain 的 Wazuh 兼容接入接口。
- `generate_benign_fixture.py`：只在文件中生成 RFC1918 正常 HTTP PCAP，不发送网络流量，用于误报回归。
- `slice_pcap_time.py`：单次流式读取经典 PCAP，按带时区的绝对时间窗口生成可复现切片与清单，不加载整个文件。
- `../../config/suricata/shieldchain-nta.rules`：ShieldChain 自定义告警规则。

当前 v11 规则集包含 95 条 ShieldChain 自定义 Suricata 规则定义（其中 2 条为 `flowbits:noalert` 关联状态规则），并结合 Zeek 元数据行为检测。935 条 final-blind 已一次性完成：754 条得到明确分类、737 条产生安全告警、181 条待研判、双引擎失败 0。这是检测覆盖率，不是准确率。详细结果见 [v11 最终盲测报告](../../docs/reports/xdr-probe-final-blind-v11-20260823.md)。

## 数据集划分与验收

比赛方提供的是一个整体 PCAP 语料，仓库所述 development（701）、validation（701）和 final-blind（935）是 ShieldChain 为避免规则过拟合而创建的工程划分，不是比赛方官方划分，也不是在训练模型。完整说明、服务器路径、冻结规则哈希和同门复现流程见 [NTA 数据集划分与独立验收](../../docs/operations/nta-dataset-split-and-evaluation.md)。

外部公开数据集的服务器目录、来源登记、恶意载荷排除和 CTU-13 操作流程见 [公开安全数据集接入说明](../../docs/operations/public-security-datasets.md)。

冻结 v11 在 CTU-13 development 上的首次外部基线、结果边界和 v12 改进方向见 [CTU-13 v11 外部 development 基线报告](../../docs/reports/ctu13-v11-external-development-baseline-20260824.md)。

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

## 大型 PCAP 时间切片

对几十 GB 的公开捕获文件，不应把全量 HTTP/连接日志一次载入内存。`nta_offline_pipeline.py` 的 Suricata、HTTP、DNS 与 Zeek 分类统计均采用流式读取；需要按官方攻击时间表取样时，使用 `slice_pcap_time.py` 在一次顺序扫描中同时写出多个窗口：

```bash
python3 scripts/nta/slice_pcap_time.py \
  /path/to/source.pcap /path/to/slices \
  --window benign-a,2018-02-21T08:30:00+00:00,2018-02-21T08:40:00+00:00 \
  --window udp-a,2018-02-21T10:15:00+00:00,2018-02-21T10:25:00+00:00 \
  --manifest /path/to/slice-manifest.json
```

时间窗口采用左闭右开区间，必须写明 UTC 偏移，名称只允许字母、数字、点、下划线和连字符。工具仅接受经典 PCAP；遇到 PCAPNG 会明确拒绝，不能静默误切。默认情况下，包头或包体不完整也会使切片失败。只有已确认损坏仅位于文件尾部时，才可显式增加 `--allow-truncated-tail`；此时清单会写入 `truncated_tail_discarded: true`，不能把丢弃行为隐藏起来。输出仍是原始网络数据，只能保存在受控数据目录，不能提交 Git。

v13 事件在兼容原有 `rule_id` 主分类的同时，在 `evidence.behavior_findings` 中记录可组合的次级行为发现。这样同一捕获可同时保留 C2 通道和 UDP/ICMP、TCP SYN 或 HTTP 请求洪泛证据；若原主分类只是“待研判”，最强行为发现才会提升为主分类。检测使用连接数、数据包速率、来源数量、失败比例等观测量，不使用文件名、场景编号、固定 IP 或官方标签作为特征。

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

## 正常流量基线

正常流量场景清单、隔离采集、保留集保护、当前 162 条 development PCAP 状态和复现命令见 [正常流量基线构建与误报验收](../../docs/operations/benign-traffic-baseline.md)。

快速冒烟测试：

```bash
python3 scripts/nta/benign_lab/run_service_lab.py database /tmp/db-smoke --limit 1
python3 scripts/nta/benign_lab/run_service_lab.py mail /tmp/mail-smoke --limit 1
python3 scripts/nta/benign_lab/run_service_lab.py dns /tmp/dns-smoke --limit 1
python3 scripts/nta/benign_lab/run_service_lab.py ssh /tmp/ssh-smoke --limit 1
python3 scripts/nta/benign_lab/run_service_lab.py smb /tmp/smb-smoke --limit 1
```

这些入口执行真实协议事务并抓取专用 Docker bridge，不会根据文件名制造检测结果。Windows 管理场景必须等待 Windows VM/测试主机。

Windows 管理采集链路已经提供：`windows_capture_plan.py` 生成受保护执行计划，隔离 Windows 控制机运行 `Collect-ShieldChainWindowsBaseline.ps1`，服务器再用 `import_windows_captures.py` 校验 SHA-256、数量和匿名文件名后导入。完整命令见正常流量基线文档；没有独立 Windows 靶机时不得伪造该部分样本。

## v12 行为检测候选

v12 在双引擎输出之后增加场景无关的 Zeek 行为聚合，不匹配文件名、家族名、场景编号或固定 IP。新增能力包括 IRC 命令序列聚合、高拒绝率目的地址扇出、周期信标、UDP/P2P 扇出、更严格的 WebShell 上下文，以及仅针对双向 TCP 的反弹连接证据。

在冻结的 development 双引擎输出上，CTU-13 明确分类覆盖达到 7/7，自建正常 development 的安全分类保持 0/180。这是开发集覆盖结果，不是准确率或生产误报率。详见 [v12 行为检测 development 报告](../../docs/reports/xdr-probe-v12-behavior-development-20260824.md)。

## v12.1 validation 候选

冻结 v12 在 CTU-13 validation 场景 2、4、13 上完成首次双引擎运行，3/3 引擎成功，输出在读取标签前锁定。validation 暴露出通用大 HTTP POST 被过度归为 WebShell；v12.1 将非命令型端点上的强异常脚本 POST 调整为“疑似 HTTP 命令控制或数据外传”。

v12.1 在正常 development 保持 0/180 安全分类，CTU development 保持 7/7 明确分类，validation 为 3/3 明确分类。由于 v12.1 已使用 validation 调整，该结果不是独立泛化成绩。详见 [v12 validation 验收报告](../../docs/reports/xdr-probe-v12-validation-20260825.md)。
