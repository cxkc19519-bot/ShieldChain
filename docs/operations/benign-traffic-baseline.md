# 正常流量基线构建与误报验收

## 目的

该基线用于回答“现有 Suricata/Zeek 规则会不会把授权的正常业务流量误报为攻击”。它不是模型训练集，也不能替代生产网络的长期流量画像。

ShieldChain 将 300 个正常场景按相关变体分组后固定划分为：

| 协议 | 总数 | development | validation | final_blind | 采集方式 |
| --- | ---: | ---: | ---: | ---: | --- |
| HTTP | 60 | 36 | 12 | 12 | 隔离 Docker 网络中的真实 HTTP |
| MariaDB | 60 | 36 | 12 | 12 | 真实 MySQL/MariaDB 协议 |
| 邮件 | 60 | 36 | 12 | 12 | 真实 SMTP 协议 |
| DNS | 30 | 18 | 6 | 6 | 真实 UDP DNS 查询 |
| SSH | 30 | 18 | 6 | 6 | 真实 SSH 密钥认证和命令 |
| SMB | 30 | 18 | 6 | 6 | 真实 SMB2/3 文件操作 |
| Windows 管理 | 30 | 18 | 6 | 6 | 必须使用 Windows VM/测试主机 |
| 合计 | 300 | 180 | 60 | 60 |  |

同一 action/profile 的两个变体始终位于同一划分，避免近重复样本泄漏。PCAP 使用哈希文件名，标签只存在于 manifest，检测器不得根据文件名推断类别。

## 当前完成状态

截至 2026-08-22，服务器已完成 Linux 容器可真实执行的 development 采集：

- HTTP 36 条；
- MariaDB 36 条；
- SMTP 邮件 36 条；
- DNS 18 条；
- SSH 18 条；
- SMB 18 条；
- 合计 162 条正式 development PCAP。

Windows 管理流量的 18 条 development 场景仍为待完成状态。不得用 Linux 命令、伪造文本或文件名标签冒充 Windows 管理流量；应连接 Windows VM/测试主机并采集真实 WinRM、SMB、RDP 或 Wazuh/Sysmon 日志。

服务器数据根目录：

```text
/home/user/jhk/nta-benign-corpus-v10
```

每种协议目录包含 `pcap/` 和 `<protocol>-development-captures.jsonl`。JSONL 记录场景 ID、匿名 PCAP 名、SHA-256、字节数和执行时间。原始 PCAP、标签清单和引擎日志不提交 Git。

## 安全隔离

- 每个协议使用独立的 Docker `--internal` 网络；
- 不发布任何主机端口，不连接校园网或生产网络；
- tcpdump 只监听该实验网络的专用 bridge；
- 容器、网络名称固定，发现同名对象时拒绝复用；
- 每条 PCAP 拒绝覆盖，失败后必须明确清理未完成输出；
- 默认只允许 development；validation/final_blind 需要显式 `--allow-held-out`；
- validation/final_blind 在规则冻结前不得用于调参；
- 自定义规则只告警，不自动阻断或处置。

## 生成 manifest

```bash
cd /home/user/jhk/shieldchain
python3 scripts/nta/benign_lab/scenario_catalog.py \
  /home/user/jhk/nta-benign-corpus-v10/manifests
```

## 采集命令

HTTP 使用独立入口：

```bash
python3 scripts/nta/benign_lab/run_http_lab.py \
  /home/user/jhk/nta-benign-corpus-v10/http-development
```

其他真实协议使用统一入口：

```bash
python3 scripts/nta/benign_lab/run_service_lab.py database \
  /home/user/jhk/nta-benign-corpus-v10/database-development
python3 scripts/nta/benign_lab/run_service_lab.py mail \
  /home/user/jhk/nta-benign-corpus-v10/mail-development
python3 scripts/nta/benign_lab/run_service_lab.py dns \
  /home/user/jhk/nta-benign-corpus-v10/dns-development
python3 scripts/nta/benign_lab/run_service_lab.py ssh \
  /home/user/jhk/nta-benign-corpus-v10/ssh-development
python3 scripts/nta/benign_lab/run_service_lab.py smb \
  /home/user/jhk/nta-benign-corpus-v10/smb-development
```

先用 `--limit 1` 做冒烟测试。若结果 JSONL 已存在，工具会拒绝覆盖。

## 离线误报评估

将正式 development PCAP 放入单独输入目录，使用现有离线链路运行 Suricata 与 Zeek：

```bash
export SHIELDCHAIN_NTA_PCAP_ROOT=/home/user/jhk/nta-benign-corpus-v10/development-linux
export SHIELDCHAIN_NTA_RESULT_ROOT=/home/user/jhk/nta-benign-corpus-v10/development-linux-analysis
python3 scripts/nta/nta_offline_pipeline.py --all
```

必须分别记录：

1. Suricata/Zeek 引擎成功处理数量；
2. ShieldChain 自定义规则告警数；
3. 触发告警的场景、协议和规则 SID；
4. 误报率及 95% 置信区间；
5. 规则版本、规则文件 SHA-256、镜像版本；
6. 未覆盖的 Windows 和真实生产流量边界。

只有完成冻结 validation/final_blind 的一次性评估，并补充生产或近生产正常流量后，才可以讨论“准确率”。development 零告警仅说明当前场景未触发自定义规则，不等于生产环境零误报。

## 2026-08-22 development 实测结果

规则文件 SHA-256：`0c87908e60f5b3d1f082292d55c3a75586c5682b5facceee488716eb4f31ec03`。

| 协议 | 样本 | Suricata 成功 | Zeek 成功 | 安全告警样本 | 安全告警数 | 被排除的信息/解码事件 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 36 | 36 | 36 | 0 | 0 | 401 |
| MariaDB | 36 | 36 | 36 | 0 | 0 | 835 |
| SMTP | 36 | 36 | 36 | 0 | 0 | 924 |
| DNS | 18 | 18 | 18 | 0 | 0 | 60 |
| SSH | 18 | 18 | 18 | 0 | 0 | 771 |
| SMB | 18 | 18 | 18 | 0 | 0 | 744 |
| 合计 | 162 | 162 | 162 | 0 | 0 | 3735 |

观察误报率为 0/162。对“这批 development 场景中的安全告警样本比例”使用零事件的单侧 95% 精确上界约为 1.83%；它不是生产误报率，也不能外推到尚未采集的 Windows、数据库高并发、真实邮件附件、加密 DNS、RDP/WinRM 或校园网业务。

第一次 SMB 评估把正常 NTLM 会话建立的 `ET INFO NTLM ...` 信息性签名错误升格为安全告警（18/18）。流水线现已将以下内容归入可审计但不升格的信息/解码事件：

- 签名以 `SURICATA ` 开头；
- 签名以 `ET INFO ` 开头；
- 分类为 `Generic Protocol Command Decode`；
- 分类为 `Not Suspicious Traffic`。

修复后 SMB 18/18 重新运行，双引擎均成功且安全告警为 0。该修复有单元测试保护；原始第一轮结果保留在服务器作为问题发现证据，不作为最终指标。

最终运行目录：

- HTTP：`http-development-analysis/run-20260822-170456`；
- MariaDB、SMTP、DNS、SSH：各协议 `development-analysis/run-20260822-195647`；
- SMB 修复回归：`smb-development-analysis-v3/run-20260822-201106`。

## 测试

不依赖 Docker 的测试：

```bash
python3 -m unittest \
  tests/scripts/test_benign_scenario_catalog.py \
  tests/scripts/test_benign_http_lab.py
```

仓库完整测试环境还会运行 `tests/scripts/test_benign_service_lab.py`，验证所有 action 都有事务构造器、bridge 名称满足 Linux 限制，并确保没有把 Windows 场景暴露为 Linux Docker 适配器。

