# Phase 0 Verification Report

## 1. 本阶段完成内容

Phase 0 已完成来源权威顺序、功能来源矩阵、论文协议分析、逐步消息账本、威胁模型、歧义与确定性决策、复现架构、实验预注册以及 Phase 1-8 主实施边界。交叉审计覆盖所有九份 Phase 0 基线文档和已批准设计规格；审计没有发现需要改写既有文档的跨文档矛盾。

本阶段只建立可审计的文档基线，没有创建 Phase 1 计划、代码、依赖、证书、测试工具、结果数据、标签或功能分支。

## 2. 修改和新增的文件

本次交叉审计新增：

- `docs/phase-0-verification.md`：本十章验证报告及可复现门禁证据。

本次审计逐一复核但未修改：

- `docs/source-index.md`
- `docs/feature-source-matrix.md`
- `docs/paper-analysis.md`
- `docs/protocol-messages.md`
- `docs/threat-model.md`
- `docs/ambiguities-and-decisions.md`
- `docs/architecture.md`
- `docs/experiment-plan.md`
- `docs/implementation-plan.md`
- `docs/superpowers/specs/2026-07-15-saga-reproduction-design.md`
- `.gitignore`

`.gitignore` 已覆盖本地论文 PDF、需求 DOCX、Office 临时文件和 `/.superpowers/`；这些输入均保持未跟踪且不出现在普通 `git status` 中。

## 3. 与论文对应的章节或协议步骤

| Phase 0 证据 | 论文映射 | 已固定的基线内容 |
|---|---|---|
| 来源索引与来源矩阵 | III-VI、Appendix D-E、Figs. 1-12 | 区分论文原始设计、复现工程补充与后续创新扩展 |
| 论文分析与消息账本 | IV-B Steps 1-6；IV-C Steps 1-7；IV-D；IV-E Steps 1-8；Figs. 7-9 | User/Agent 注册、策略与 OTK、Agent 通信、DH/KDF、ACT 签发与使用 |
| 威胁模型与歧义决策 | III-C-D；IV-F；Appendix D-E；Table IV | C1-C6、A1-A8、三项形式化安全属性、reachability sanity checks 与工程测试边界 |
| 架构与实验计划 | IV-B-IV-F；Appendix D-E；VI | 端口/适配器边界、20 项攻击、并发原子性、真实 TLS/mTLS、ProVerif 与方向性性能门禁 |
| 主实施计划 | IV-B-IV-E 基础复现；IV-F/Appendix D；Appendix E；VI | Phase 1-8 的 TDD、提交、退出和创新锁定边界 |

ACT 明文在全部基线材料中保持论文的五字段语义：`<N, T_issued, T_expire, Q_max, PAC_B>`，工程命名为 `nonce`, `issued_at`, `expires_at`, `q_max`, `initiating_agent_access_control_public_key`。

## 4. 关键设计决策

- 论文明确公式/步骤优先于图示；因此 Provider 签名采用 IV-C Step 7 的 `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>`，同时保留 Figure 8 的冲突记录。
- OTK 用户签名采用 IV-C Step 2 和 IV-E Step 3 的 `<aid_A, OTK_A^i>`；Figure 8 省略 `aid_A` 的差异不被静默覆盖。
- 基础 ACT 不增加 task、tool、resource、Agent ID、Token ID 或 context hash 字段；任务绑定缺失是论文局限，未来能力令牌必须属于独立 Token 家族和后续分支。
- Ed25519、X25519、HKDF-SHA256 固定域分离参数、ChaCha20-Poly1305/AAD、确定性 JSON、严格 Base64URL、Unix milliseconds、scrypt、半开时间区间和 future-issued 拒绝均为复现工程选择，不冒充论文原始字段或证明结论。
- Provider 维持论文的诚实但好奇边界；外部身份服务、公共可达性、DoS 防护、安全注册表和密码学原语安全均按论文假设处理。
- 合法的同一 Agent ACT 复用、错误 Agent 转移、过期/耗尽使用、TLS 记录重放和应用语义重复请求分别建模。
- ProVerif 只承载 Token secrecy、Agent-Provider authentication、Agent-Agent authentication 三类安全属性；reachability 只作为模型可执行性/非空性 sanity check。
- OTK、pair budget、SOTK 与 `q_max` 的持久化、CAS、线性化和崩溃边界是复现工程加固，不能由论文形式化结果代替。

## 5. 已运行的测试命令

以下是 Windows PowerShell 中实际运行的 Step 1 命令。brief 内两个损坏的 Unicode 字符串被恢复为语义等价的 `稍后`+`填写` 与 `以后`+`补充`；其余模式保持字符串拼接，以避免报告本身触发占位符扫描。

```powershell
$placeholderPattern = @('TB'+'D','TO'+'DO','implement '+'later','fill in '+'details','similar '+'to','稍后'+'填写','以后'+'补充') -join '|'
$placeholderOutput = @(rg -n $placeholderPattern docs --glob '!superpowers/**')
$placeholderExit = $LASTEXITCODE
"CHECK placeholder exit=$placeholderExit match_lines=$($placeholderOutput.Count)"
$placeholderOutput

git diff --check
"CHECK diff_check exit=$LASTEXITCODE"

$actExtensionOutput = @(rg -n 'task_id|issuer_agent_id|subject_agent_id|protocol_context_hash' docs/paper-analysis.md docs/protocol-messages.md)
$actExtensionExit = $LASTEXITCODE
"CHECK act_extension exit=$actExtensionExit match_lines=$($actExtensionOutput.Count)"
$actExtensionOutput

$futureOutput = @(rg -n 'Agent-to-Tool|Risk-adaptive|Prompt-injection' docs/feature-source-matrix.md docs/architecture.md docs/implementation-plan.md)
$futureExit = $LASTEXITCODE
"CHECK future_features exit=$futureExit match_lines=$($futureOutput.Count)"
$futureOutput
```

以下是实际运行的 Step 2 命令。brief 中损坏的矩阵表头正则被恢复为仓库文件中的真实 Unicode 表头。

```powershell
$required = @(
  'docs/source-index.md',
  'docs/feature-source-matrix.md',
  'docs/paper-analysis.md',
  'docs/protocol-messages.md',
  'docs/threat-model.md',
  'docs/ambiguities-and-decisions.md',
  'docs/architecture.md',
  'docs/experiment-plan.md',
  'docs/implementation-plan.md'
)
$missing = @($required | Where-Object { -not (Test-Path $_) })
"CHECK required_files exit=$(if ($missing.Count -eq 0) {0} else {1}) present=$($required.Count - $missing.Count) missing=$($missing.Count)"
$missing | ForEach-Object { "Missing $_" }

$actTupleOutput = @(rg -n 'nonce.*issued_at.*expires_at.*q_max.*access.control.public.key|N.*T_issued.*T_expire.*Q_max.*PAC_B' docs)
$actTupleExit = $LASTEXITCODE
"CHECK act_tuple exit=$actTupleExit match_lines=$($actTupleOutput.Count)"
$actTupleOutput

$headerOutput = @(rg -n '功能.*论文原始设计.*复现工程补充.*后续创新扩展' docs/feature-source-matrix.md)
$headerExit = $LASTEXITCODE
"CHECK matrix_header exit=$headerExit match_lines=$($headerOutput.Count)"
$headerOutput

$coreOutput = @(rg -n 'IV-B|IV-C|IV-D|IV-E' docs/paper-analysis.md docs/protocol-messages.md docs/feature-source-matrix.md)
$coreExit = $LASTEXITCODE
"CHECK core_sections exit=$coreExit match_lines=$($coreOutput.Count)"
$coreOutput
```

提交前还实际运行：

```powershell
git check-ignore -v -- 'SAGA，A Security Architecture for Governing AI Agentic Systems.pdf' '具体要求.docx' '.superpowers/sdd/task-7-brief.md'
git status --short --ignored
git diff --check
git diff --cached --check
git diff --cached --name-only
```

## 6. 测试结果

首次运行 Step 1-2 的实际结果如下；新增本报告后的最终重跑结果记录在本节后续条目中，并作为提交门禁使用。

- 占位符扫描：exit `1`，匹配行 `0`；对 `rg` 而言 exit 1 表示无匹配，符合预期。
- 工作区 whitespace 检查：exit `0`。
- 基础 ACT 扩展字段扫描：exit `1`，匹配行 `0`；两份规范协议文档未把扩展字段写入基础 ACT。
- 后续功能扫描：exit `0`，匹配行 `8`；逐行复核后全部位于 non-goal、deferred、future innovation 或 branch-gate 语境。
- 必需文件检查：exit `0`，存在 `9`，缺失 `0`。
- 五字段 ACT 扫描：首次 exit `0`，匹配行 `15`。
- 矩阵精确表头扫描：exit `0`，匹配行 `1`。
- IV-B/IV-C/IV-D/IV-E 引用扫描：exit `0`，匹配行 `136`；三份指定文档均覆盖四个核心协议部分。
- `git check-ignore -v`：三项本地输入全部命中 `.gitignore`；`git status --short --ignored` 只显示三个预期 ignored 条目。
- 新增本报告后的完整 Step 1-2 重跑：占位符 `exit=1/match_lines=0`，whitespace `exit=0`，ACT 扩展字段 `exit=1/match_lines=0`，后续功能 `exit=0/match_lines=8`，必需文件 `exit=0/present=9/missing=0`，五字段 ACT `exit=0/match_lines=17`，矩阵表头 `exit=0/match_lines=1`，核心章节 `exit=0/match_lines=136`（`paper-analysis=22`、`protocol-messages=66`、`feature-source-matrix=48`）。十章标题检查为 `exit=0/count=10`。
- 最终重跑、cached diff 和提交后的真实结果见本次任务的 `.superpowers/sdd/task-7-report.md`；该报告为本地审计记录，不进入 Git。

## 7. 尚未解决的问题

以下仅是论文自身或其威胁模型留下的限制，不是尚未选择的复现方案：

- 论文不保护主动恶意 Provider，也不覆盖被篡改/回滚的注册表、CA/密码学原语失效或良性 User 凭据被盗。
- 外部持久身份/真人验证、全局公网可达性、NAT 穿透、基础设施 DoS/洪泛防护均是外部假设，基础复现不能证明这些能力。
- 论文没有定义跨 Provider/Agent 状态域的分布式回滚、崩溃安全删除或 ACT 使用计数与外部应用副作用的 exactly-once 语义。
- ACT 没有请求 ID 或幂等键，因此不能声称检测同一合法 Agent 的应用语义重复请求。
- Provider 可观察注册元数据和流量模式；论文没有提供针对诚实但好奇 Provider 的元数据隐私保证。

## 8. 与论文的已知差异

- IV-C Step 7 与 Figure 8 的 Provider 签名字段不同；同时 Figure 8 的 OTK 签名图示省略 `aid_A`。基线按正文公式实现并保留差异。
- IV-E Step 6 要求 `A` 验证 `Cert_U2`，但 Step 5 和 Figure 9 没有说明该证书的传输来源；未来具体供给路径必须标注为工程补充。
- III-D 的 C4 使用“TLS public keys”共享措辞；仅共享 TLS 公钥的安全意义不完整，基线原样记录而不改写成不同密钥材料。
- 论文把 ACT 描述为 task-scoped，但五字段元组没有 task 字段，因此基础 ACT 不具备密码学任务绑定。
- IV-E Step 8 没有明确独立的 future-issued/not-before 检查；半开区间和 future-issued 拒绝属于工程规则。
- Appendix D 的 reachability 查询仅是模型可达性 sanity check，不是第四项安全属性。
- 论文使用抽象密码学与未指定编码；本项目的具体算法、编码、持久化、并发和性能门禁都是显式分类的复现补充。

## 9. 下一阶段计划

Phase 1 仅在用户书面接受本 Phase 0 报告后才可开始。获批后，下一步也只是先为“Canonical serialization and cryptographic foundations”编写独立、逐测试、逐文件、逐提交的 TDD 详细计划；本报告不创建该计划，也不授权实现、安装依赖、生成证书或启动服务。

Agent-to-Tool、risk-adaptive authorization、prompt-injection defense、主动 ACT revocation、RAFT/PBFT、分片、联邦和 A2A 继续保持在基础复现之外。

## 10. 需要确认的问题

请用户确认是否接受本 Phase 0 十章报告、九份基线文档、已批准设计决策、论文局限/差异以及 Phase 1-8 边界。用户接受之前，Phase 1 不得开始；也不得创建 Phase 1 计划、代码、依赖、凭据、标签或工具授权分支。
