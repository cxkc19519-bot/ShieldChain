# ATT&CK 技战术图谱与智能研判映射指南

本指南描述了 MITRE ATT&CK 框架中常见的技战术，并指导 ShieldChain 智能体如何在海量日志中识别和归类这些攻击阶段。

## 战术 1: 初始访问 (Initial Access - TA0001)
攻击者尝试进入企业网络的初始步骤。
- **钓鱼邮件 (Phishing - T1566)**：
  - **行为特征**：带有恶意附件（如宏文档、伪装的可执行文件）或恶意链接的电子邮件。
  - **关联数据**：邮件网关日志、Office 365 审计日志。
  - **处置策略**：智能体需提取发件人域名、附件 Hash 及邮件内容，交由威胁情报中心比对。

## 战术 2: 执行 (Execution - TA0002)
攻击者在目标系统上运行恶意代码。
- **命令与脚本解释器 (Command and Scripting Interpreter - T1059)**：
  - **行为特征**：异常调用 PowerShell、cmd.exe、bash、python 等执行编码过或混淆的命令（如 `powershell -enc ...`）。
  - **关联数据**：EDR 进程创建日志、Sysmon Event ID 1 (Process Create)。
  - **处置策略**：检测到高危命令行时，立即记录父子进程树结构。

## 战术 3: 持久化 (Persistence - TA0003)
攻击者在系统重启或更改凭据后保持对系统的访问权限。
- **计划任务/作业 (Scheduled Task/Job - T1053)**：
  - **行为特征**：利用 `schtasks` 或 `cron` 创建异常的定时任务，执行未知路径下的脚本。
  - **关联数据**：Windows 事件日志 (4698 - A scheduled task was created)、Linux syslog。
  - **处置策略**：查询定时任务执行的实体文件信誉度。

## 战术 4: 权限提升 (Privilege Escalation - TA0004)
攻击者获取更高层级的系统权限（如从普通用户到 SYSTEM/root）。
- **滥用提权机制 (Abuse Elevation Control Mechanism - T1548)**：
  - **行为特征**：利用 UAC 绕过技术、或者利用 sudo 配置漏洞获取 root 权限。
  - **关联数据**：认证日志 (auth.log)、Windows 安全日志。
  - **处置策略**：监控意外的特权令牌获取事件。

## 战术 5: 横向移动 (Lateral Movement - TA0008)
攻击者在网络环境中漫游，寻找有价值的目标。
- **远程服务 (Remote Services - T1021)**：
  - **行为特征**：利用 SMB/Windows Admin Shares、RDP、SSH、WinRM 等进行跨主机的非正常访问。
  - **关联数据**：网络流量日志、防火墙日志、Windows 安全日志 (4624 Logon)。
  - **处置策略**：识别非工作时间、非管理员 IP 发起的横向连接，结合凭证窃取事件进行联合研判。

## 总结
ShieldChain 的核心优势在于将孤立的安全告警（如单一的 Powershell 执行告警）映射到整个 ATT&CK 战术链条中，从而判断出完整的攻击生命周期。
