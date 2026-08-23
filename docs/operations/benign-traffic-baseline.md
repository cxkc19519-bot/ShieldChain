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

截至 2026-08-23，本地与服务器已完成可真实执行的 development 采集：

- HTTP 36 条；
- MariaDB 36 条；
- SMTP 邮件 36 条；
- DNS 18 条；
- SSH 18 条；
- SMB 18 条；
- Windows 管理 18 条（本地隔离 Hyper-V 网络采集，已导入服务器）；
- 已采集、验签、导入并完成双引擎检查的 development PCAP 合计 180 条。

服务器现已正式保存全部 180 条 development PCAP。Windows 18 条的首轮检查发现两类正常 WinRM 误报；修正规则与告警分级后再次检查，18/18 个样本的 Suricata 与 Zeek 均成功执行，安全告警样本数为 0。首轮与修复后结果均保留，便于审计规则调整过程。

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

## Windows 管理流量采集

Windows 场景必须在隔离实验网中使用一台 Windows 控制机和一台 Windows 测试机；也可像本次实测一样，由 Windows 宿主机在 Hyper-V 内部交换机上控制隔离 Windows VM。仓库不会把 Linux 命令、文本记录或文件名标签伪装成 Windows 管理样本。

前置条件：

- 控制机和靶机均为测试资产，地址位于 RFC1918 私网或链路本地网段；
- 靶机已显式启用 WinRM，并配置三个测试角色账号；也可冒烟测试时使用一个账号；
- 控制机安装 Wireshark，能以管理员权限运行 `dumpcap.exe`；
- 软件安装场景使用专门制作的无害测试 MSI，禁止使用生产安装包；
- 最好将两台主机置于专用虚拟交换机/VLAN，禁止连接生产网络。

先在仓库中生成只含固定 development 场景的执行计划：

```powershell
python scripts/nta/benign_lab/windows_capture_plan.py windows-development-plan.json
```

项目提供可审计的无害 MSI 源码，只安装一份说明文本，不创建服务、不修改防火墙、不联网。使用 WiX v5 构建：

```powershell
wix build `
  .\scripts\nta\benign_lab\ShieldChainBenignFixture.wxs `
  -out D:\ShieldChainLab\ShieldChainBenignFixture.msi
```

在管理员 PowerShell 中查看网卡编号：

```powershell
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
```

执行 18 条真实 WinRM 管理事务并逐场景采集 classic PCAP：

```powershell
.\scripts\nta\benign_lab\Collect-ShieldChainWindowsBaseline.ps1 `
  -PlanPath D:\ShieldChainLab\windows-development-plan.json `
  -OutputDirectory D:\ShieldChainLab\captures\windows-development `
  -TargetHost 192.168.56.20 `
  -CaptureInterface 6 `
  -DumpcapPath D:\Wireshark\dumpcap.exe `
  -LabMsiPath D:\ShieldChainLab\ShieldChainBenignFixture.msi `
  -CredentialDirectory D:\ShieldChainLab\credentials
```

采集器会执行真实的临时文件删除、测试 MSI 安装/卸载、计划任务创建/删除和专用注册表值写入/删除；所有写操作均限制在 `ShieldChainBenignLab` 名称空间。默认按三个 profile 分别提示输入凭据；`-CredentialDirectory` 可加载当前 Windows 用户用 `Export-Clixml` 保存的 DPAPI 凭据，密码不以明文写入脚本或日志；冒烟时可用 `-UseSingleCredential`。

将输出目录复制到服务器后先验签、验数量，再导入正式语料：

```bash
python3 scripts/nta/benign_lab/import_windows_captures.py \
  /home/user/jhk/incoming/windows-development \
  /home/user/jhk/nta-benign-corpus-v10/windows-development
```

导入器校验 18 个场景、匿名文件名、大小和 SHA-256，拒绝重复、缺失、篡改或覆盖。`validation` 与 `final_blind` 各 6 条，只有规则冻结后才能显式添加 `--allow-held-out` 生成计划和导入。

## 2026-08-23 Windows development 本地采集验收

- 隔离网络：Hyper-V 内部交换机 `ShieldChain-Lab`，宿主机 `192.168.56.1/24`，来宾机 `192.168.56.20/24`，无 NAT；
- 场景：临时文件操作 6 条、无害 MSI 安装/卸载 6 条、计划任务 4 条、注册表操作 2 条；
- 账号：`interactive_admin` 4 条、`automation_account` 6 条、`security_operator` 8 条；
- 文件：18/18 个 classic PCAP，合计 2,073,482 字节，单文件 3,545–354,825 字节；
- 完整性：JSONL 18 条，文件数量、大小和 SHA-256 不一致数为 0；
- 协议：18/18 个文件均含 TCP/5985 WinRM 流量，每文件 14–382 个 WinRM 数据包；
- 清理：临时文件、远端 MSI、测试计划任务、测试注册表值、已安装 fixture 文件残留均为 0；
- 本地目录：`D:\ShieldChainLab\captures\windows-development-20260823-b`；
- 服务器正式目录：`/home/user/jhk/nta-benign-corpus-v10/windows-development`；
- 当前边界：只覆盖隔离实验室中的 WinRM HTTP（TCP/5985）管理操作，不覆盖 WinRM HTTPS、自定义端口、RDP、域环境横向管理或真实生产管理流量。

### Windows 首轮误报、修正与回归

首轮运行目录为 `/home/user/jhk/nta-benign-corpus-v10/windows-development-analysis/run-20260823-125455`。18/18 个样本的两台引擎均成功，但全部样本被判为含安全告警，共计 330 条安全告警：

- 318 条 ET SID `2026850`（`WinRM User Agent Detected - Possible Lateral Movement`）；
- 12 条自定义 SID `9000005`（异常大的 HTTP POST）。

诊断确认两者均由合法 WinRM 管理造成。SID `2026850` 只能证明出现 WinRM 客户端特征，不能单独证明横向移动，因此流水线继续保留原始事件，但将它单列为“上下文观察”，不再直接升级为安全结论。SID `9000005` 的通用 HTTP 大请求规则会命中 WinRM SOAP/MSI 传输，现仅排除标准 WinRM 端口 5985/5986；其他端口上的大 HTTP POST 仍由该规则检测。

修正后的规则文件 SHA-256 为 `e4ee9be7800b2a39d3bf227c63d783186c8f7b2be6100d0af709dd1dea181d2b`。第二轮运行目录为 `/home/user/jhk/nta-benign-corpus-v10/windows-development-analysis-v2/run-20260823-131029`，结果为：

- Suricata 成功 18/18，Zeek 成功 18/18；
- 安全告警样本 0/18，安全告警 0；
- 原始 Suricata 事件 4,020 条，其中信息/解码事件 3,702 条，上下文观察 318 条；
- 结果分类均为“网络行为待研判”，不会把合法 WinRM 自动判成攻击。

为防止降低攻击检测能力，使用 development 攻击集中的 12 个代表性 PCAP 做规则回归（未使用 validation 或 final_blind 调参）。结果目录为 `/home/user/jhk/nta-dataset/results-winrm-rule-regression/run-20260823-131813`：12/12 个样本双引擎执行成功，12/12 仍被检测为“数据库攻击与数据提取”，累计产生 15 条安全告警。该回归只证明本次修正没有破坏这 12 个已选样本，不能替代冻结集验收。

## 2026-08-23 validation 实测结果

规则和流水线冻结后，重新采集并一次性分析了 60 条 validation 正常流量：HTTP、MariaDB、SMTP 各 12 条，DNS、SSH、SMB、Windows 管理各 6 条。Windows validation 位于本地 `D:\ShieldChainLab\captures\windows-validation-20260823-v10` 和服务器 `/home/user/jhk/nta-benign-corpus-v10/windows-validation`。

- Suricata 成功 60/60，Zeek 成功 60/60；
- 安全告警样本 0/60，安全告警 0；
- 上下文观察 83 条，均来自正常 WinRM；
- 信息/解码事件 2,183 条；
- 零事件的单侧 95% 精确上界约为 4.87%；该值只描述本轮隔离场景，不是生产误报率。

运行目录为 `/home/user/jhk/nta-benign-corpus-v10/validation-all-v10-analysis/run-20260823-134702`。只读锁定摘要为 `/home/user/jhk/nta-dataset-blind/evaluation/benign-validation-v10-locked-result.json`，SHA-256 为 `ab6f3461730ff389577067c1ab1b0758334c9ad2b1141cdbe3688a89d087b3a6`。`final_blind` 仍未运行。
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

## 2026-08-22 至 2026-08-23 development 实测结果

Linux 协议评测使用的规则文件 SHA-256：`0c87908e60f5b3d1f082292d55c3a75586c5682b5facceee488716eb4f31ec03`；Windows 修复回归使用的规则文件 SHA-256 见上文。

| 协议 | 样本 | Suricata 成功 | Zeek 成功 | 安全告警样本 | 安全告警数 | 信息/解码/上下文观察 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 36 | 36 | 36 | 0 | 0 | 401 |
| MariaDB | 36 | 36 | 36 | 0 | 0 | 835 |
| SMTP | 36 | 36 | 36 | 0 | 0 | 924 |
| DNS | 18 | 18 | 18 | 0 | 0 | 60 |
| SSH | 18 | 18 | 18 | 0 | 0 | 771 |
| SMB | 18 | 18 | 18 | 0 | 0 | 744 |
| Windows 管理 | 18 | 18 | 18 | 0 | 0 | 4,020（含 318 条上下文观察） |
| 合计 | 180 | 180 | 180 | 0 | 0 | 7,755 |

观察到的安全告警样本比例为 0/180。对“这批 development 场景中的安全告警样本比例”使用零事件的单侧 95% 精确上界约为 1.65%；它不是生产误报率，也不能外推到数据库高并发、真实邮件附件、加密 DNS、RDP、WinRM HTTPS/自定义端口、域环境横向管理或校园网业务。

第一次 SMB 评估把正常 NTLM 会话建立的 `ET INFO NTLM ...` 信息性签名错误升格为安全告警（18/18）。流水线现已将以下内容归入可审计但不升格的信息/解码事件：

- 签名以 `SURICATA ` 开头；
- 签名以 `ET INFO ` 开头；
- 分类为 `Generic Protocol Command Decode`；
- 分类为 `Not Suspicious Traffic`。

修复后 SMB 18/18 重新运行，双引擎均成功且安全告警为 0。该修复有单元测试保护；原始第一轮结果保留在服务器作为问题发现证据，不作为最终指标。

最终运行目录：

- HTTP：`http-development-analysis/run-20260822-170456`；
- MariaDB、SMTP、DNS、SSH：各协议 `development-analysis/run-20260822-195647`；
- SMB 修复回归：`smb-development-analysis-v3/run-20260822-201106`；
- Windows 首轮：`windows-development-analysis/run-20260823-125455`；
- Windows 修复回归：`windows-development-analysis-v2/run-20260823-131029`；
- 攻击样本规则回归：`/home/user/jhk/nta-dataset/results-winrm-rule-regression/run-20260823-131813`。

## 测试

不依赖 Docker 的测试：

```bash
python3 -m unittest \
  tests/scripts/test_benign_scenario_catalog.py \
  tests/scripts/test_benign_http_lab.py
```

仓库完整测试环境还会运行 `tests/scripts/test_benign_service_lab.py`，验证所有 action 都有事务构造器、bridge 名称满足 Linux 限制，并确保没有把 Windows 场景暴露为 Linux Docker 适配器。

