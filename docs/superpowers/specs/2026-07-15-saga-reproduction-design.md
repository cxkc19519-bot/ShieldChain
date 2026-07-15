# SAGA 论文复现设计规格

**日期：** 2026-07-15  
**状态：** 已完成对话确认，等待书面规格复核  
**规范来源：** *SAGA: A Security Architecture for Governing AI Agentic Systems*（NDSS 2026 版本）

## 1. 目标与验收口径

本项目独立实现论文中的基础 SAGA。论文协议文本是唯一规范来源；作者公开代码只用于交叉验证和解释实现选择，不能覆盖论文协议，也不能把参考实现的行为自动归类为论文原始设计。

“基础 SAGA 已正确复现”必须同时满足：

1. 论文 IV-B 至 IV-E 的协议步骤、字段、密钥关系、签名对象和验证动作均有实现与自动化测试映射。
2. Provider 与 Agent 的真实网络服务使用 X.509 证书和双向 TLS；单进程协议核心只作为中间里程碑。
3. 单元测试、协议测试、安全攻击测试、并发原子性测试和 mTLS 端到端测试全部通过。
4. ProVerif 独立验证 Token 保密性、Agent-Provider 认证和 Agent-Agent 认证。
5. 性能实验复现论文中的方向性趋势，并完整记录环境、样本、参数和与论文结果的偏差；跨硬件绝对数值不作为硬门槛。
6. 功能来源矩阵不存在未分类功能、字段、测试或指标。
7. 论文歧义、工程决策、未覆盖安全属性和已知差异均已形成文档。

基础 SAGA 达到以上门禁前，不创建或实现 Agent 工具调用授权、风险自适应 Token、提示词注入检测或主动 Token 撤销机制。

## 2. 来源优先级与范围隔离

发生冲突时按以下顺序裁决：

1. 论文协议正文中的明确公式和步骤；
2. 论文协议图和符号表；
3. 论文实现与评估章节；
4. 本规格中明确标注的复现工程决策；
5. 作者参考实现的观察结果。

如果同一层级内部不一致，不静默选择：在 `docs/ambiguities-and-decisions.md` 中并列记录证据、选择和影响，并在功能来源矩阵中标注。

### 2.1 功能来源矩阵

项目维护 `docs/feature-source-matrix.md`，固定使用以下四列：

| 功能 | 论文原始设计 | 复现工程补充 | 后续创新扩展 |
|---|---|---|---|
| ACT 明文 | `N, T_issued, T_expire, Q_max, PAC_B`（IV-E Step 7、Fig. 9） | 确定性编码、Base64URL、外层消息版本 | Tool/task/resource 约束 |
| OTK 发放 | 每次请求返回一个 OTK、pair budget、发放后递减（IV-D、IV-E Step 2） | 原子事务、稳定错误类型、审计事件 | 风险自适应配额 |
| Token 使用 | 有效期和 `Q_max` 内复用、绑定 `PAC_B`（IV-E Steps 7-8） | 并发安全计数、可注入 Clock | 委托深度、动态确认 |
| 策略更新 | 新的联系申请受新策略约束（IV-D） | 明确事务隔离和计数器更新语义 | 主动撤销已签发 Token |

矩阵约束：

- 每个可执行功能、协议字段、安全测试和性能指标至少对应一行。
- 论文列必须指向节号、步骤、公式、图或表。
- 作者代码行为只能写在工程补充列或单独的“参考实现观察”中。
- 同一行可以同时有论文机制和工程实现，但二者必须分别落入对应列。
- 创新扩展列只描述未来方向，不链接到基础运行时代码。
- 代码评审发现未分类项目时，稳定性门禁失败。

## 3. 总体架构

采用“纯协议核心 + 基础设施适配层”的模块化研究原型。

### 3.1 组件边界

1. `domain`：User、Agent、Endpoint、Contact Policy、OTK、ACT 等不可变领域模型；不依赖 Web 框架、数据库或具体密码库。
2. `crypto`：确定性序列化、签名、证书、X25519、HKDF 和 AEAD；仅封装成熟密码库。
3. `protocols`：用户注册、Agent 注册、联系解析、OTK 发放、Token 建立和 Token 使用状态机。
4. `ports`：用户/Agent 注册表、Clock、随机源、身份验证器、密码存储和原子计数器接口。
5. `adapters`：内存与 SQLite 持久化、FastAPI/HTTP、mTLS、证书和配置加载。
6. `verification`：ProVerif、安全攻击、性能基准和论文结果对照；与运行时代码隔离。

### 3.2 依赖方向

`domain` 不依赖其他项目包；`crypto` 只依赖领域值对象和成熟密码库；`protocols` 依赖 `domain`、`crypto` 和 `ports`；`adapters` 实现 `ports` 并调用 `protocols`。FastAPI 路由不得包含协议判断，持久化适配器不得决定授权策略。

### 3.3 预计目录

```text
src/saga/
├── domain/
├── crypto/
├── protocols/
├── ports/
└── adapters/
    ├── persistence/
    └── http/
tests/
├── unit/
├── protocol/
├── integration/
├── security/
└── performance/
verification/proverif/
results/
scripts/
```

## 4. 密码学设计

论文规范要求安全签名、证书、DH、KDF、哈希和对称加密，但部分具体算法与编码未被协议层固定。基础复现采用：

- 用户与 Provider 签名：Ed25519；
- Agent 长期访问控制密钥及 OTK：X25519；
- 共享密钥派生：HKDF-SHA256，`salt=None`，`info=b"SAGA-ACT-DERIVE/v1"`；
- ACT 认证加密：ChaCha20-Poly1305，`aad=b"SAGA-ACT/v1"`；
- 身份凭证：测试 CA 签发的 X.509 证书；
- 密码存储：scrypt，基线参数 `N=2^15, r=8, p=1, dkLen=32`，每个密码使用 16 字节密码安全随机 salt；
- 哈希：SHA-256；
- 时间：整数 Unix milliseconds；
- 二进制字段：无填充 Base64URL；
- 签名与哈希输入：UTF-8、固定字段顺序、拒绝浮点安全字段的确定性 JSON。

具体算法、KDF 域分离、AEAD AAD、scrypt 参数和确定性编码属于复现工程补充；签名、身份绑定、DH、KDF、Token 加密及验签语义属于论文原始设计。

不得自行实现底层密码算法，不得用普通字符串哈希模拟签名、证书、KDF 或加密。

## 5. 协议与数据流

### 5.1 User Registration

1. User 选择 `uid_U` 和密码，生成签名密钥 `(PK_U, SK_U)`。
2. CA 为 `⟨uid_U, PK_U⟩` 签发证书 `Cert_U`。
3. User 验证 Provider 证书并建立 TLS。
4. User 提交 `uid_U`、密码和 `Cert_U`。
5. Provider 通过 `IdentityVerifier` 验证持久身份及人类注册条件，拒绝重复用户。
6. Provider 使用 scrypt 派生密码验证值，保存 `⟨password_record, Cert_U⟩` 并确认注册。

外部 OpenID Connect 不作为本地研究原型的强依赖。`IdentityVerifier` 是明确的端口：测试中使用确定性可信实现，网络演示中使用本地受信身份记录；这属于对论文外部身份服务假设的工程替身，不被表述为复现 OpenID Connect。

### 5.2 Agent Registration

User 为 Agent A 生成：

- `aid_A = uid_U:name_A` 和 `ED_A = ⟨device_A, IP_A, port_A⟩`；
- TLS 凭证 `(PK_A, SK_A)` 及绑定 `⟨aid_A, PK_A⟩` 的 `Cert_A`；
- 长期访问控制密钥 `(PAC_A, SAC_A)`；
- 一批 `(OTK_A^i, SOTK_A^i)`。

User 签署：

```text
sigma_A^U = Sign_SK_U(aid_A, ED_A, PK_A, PAC_A, PK_Prov)
sigma_OTKi^U = Sign_SK_U(aid_A, OTK_A^i)
```

Provider 验证用户凭证、`aid_A` 与 `ED_A` 全局唯一性、Agent 证书及全部签名，保存元数据、联系策略和公开 OTK。Agent 本地保存 `SK_A`、`SAC_A` 和全部 `SOTK_A^i`。

Provider 按 IV-C Step 7 的正文公式签署：

```text
sigma_A^Prov = Sign_SK_Prov(aid_A, Cert_A, ED_A, PAC_A, sigma_A^U)
```

Appendix Figure 8 对该签名对象的排版与正文存在不一致；复现采用正文公式，并把差异写入歧义清单和来源矩阵。

### 5.3 Contact Policy 与 OTK

- Contact Policy 是按 Agent ID 模式匹配的规则集合，每条规则包含 OTK budget。
- 多条规则匹配时选择最具体规则；精确 Agent ID 高于用户域通配符，高于 Agent 类型通配符，高于全局通配符。
- 同等具体度的重叠规则在注册或更新时拒绝，避免依赖输入顺序。
- `budget=-1` 表示拒绝；无匹配规则与预算耗尽使用不同错误。
- 首次 `(receiving, initiating)` 联系时，根据当时最具体规则初始化 pair counter。
- 每次解析联系请求，在一个事务内完成策略读取、Agent 活跃检查、pair counter 检查与递减、OTK 可用检查及单个 OTK 消费。
- 已发放 OTK 不可再次发放；receiving Agent 成功完成 DH 后删除对应 SOTK。
- 用户补充 OTK 不重置 pair counter。
- 策略更新对新的 OTK 请求立即生效；下一次请求重新计算规则并把剩余额度限制为 `min(旧剩余额度, 新预算)`。若新规则拒绝，则立即拒绝新请求；提高预算不恢复已经消费的额度。

最后三条计数器更新规则是确定性的工程决策，用于补足论文未说明的策略更新细节。

### 5.4 Inter-Agent Communication

设 B 为 initiating Agent，A 为 receiving Agent：

1. B 与 Provider 建立 TLS，提交 `aid_B` 和 `aid_A`。
2. Provider 执行策略与 OTK 原子事务，返回 `Cert_U1`、`aid_A`、`ED_A`、`Cert_A`、`PAC_A`、`OTK_A^i`、`sigma_OTKi^U1` 和 `sigma_A^U1`。
3. B 验证 A 的用户证书、Agent 证书、用户对 Agent 元数据的签名和用户对 OTK 的签名。
4. B 与 A 建立 mTLS，双方验证 Agent 证书。
5. B 向 A 发送自身 Agent 信息、`sigma_B^U2`、`sigma_B^Prov` 和 `OTK_A^i`。
6. A 验证 B 的用户证书、Agent 证书和覆盖 B 注册信息及 `sigma_B^U2` 的 Provider 签名，并确认 `OTK_A^i` 对应的 SOTK 仍在本地且未消费。
7. B 计算 `DH_B = X25519(SAC_B, OTK_A^i)`；A 计算 `DH_A = X25519(SOTK_A^i, PAC_B)`；双方用固定 HKDF 参数得到同一 `SDHK`。
8. A 原子标记并删除 `SOTK_A^i`，生成 ACT，使用 `SDHK` 加密，保存 Token 状态并把密文交给 B。
9. B 在后续 mTLS 请求中携带同一 ACT；A 解密并验证身份绑定、时间和额度，然后原子递增成功使用次数。

## 6. ACT 模型与生命周期

论文 ACT 明文严格保持：

```text
nonce
issued_at
expires_at
q_max
initiating_agent_access_control_public_key
```

`version` 位于协议消息外层；`token_id`、`issuer_agent_id`、`subject_agent_id`、`task_id`、`protocol_context_hash`、工具、操作、参数和资源约束均不进入基础 ACT。

生命周期规则：

- A 创建、加密并保存 Token 状态；B 保存密文并在请求中携带。
- 同一 B 在未过期且未达到 `q_max` 时重复使用同一 ACT 是合法行为。
- A 将 mTLS 认证出的 B 映射到其注册 `PAC_B`，并与 ACT 中公钥做常量时间语义等价检查；其他 Agent 使用该 Token 时拒绝。
- 有效期判断使用可注入 Clock；边界采用半开区间 `[issued_at, expires_at)`。
- 请求额度在一个原子事务内执行“检查 `< q_max` 并递增”；`q_max=1` 的并发请求只能成功一个。
- 达到上限、过期或任务完成时，双方丢弃 Token；需要继续联系时重新申请 OTK。
- 策略更新和 Agent 停用阻止新的发现与 OTK 发放；已签发 Token 等待自然过期或耗尽，不实现撤销列表。

重放边界：TLS 负责网络记录层重放防护；ACT 本身按论文设计可复用。基础 SAGA 不声称检测同一合法 Agent 在额度内重复提交语义相同的应用请求，因为论文没有请求 ID 或应用幂等字段。“Token 重放”测试必须区分合法复用、错误 Agent 的 Token 转移、过期/耗尽 Token 再用和 TLS 报文重放。

论文称 ACT 面向具体任务，但原始字段不含任务标识。本复现记录该局限，不通过加入 `task_id` 修改基础协议。

## 7. 失败语义与可观察性

领域层定义稳定的失败类别：输入无效、身份验证失败、签名或证书无效、重复注册、策略拒绝、预算耗尽、OTK 池耗尽、OTK 已消费、Agent 停用、Token 身份不匹配、Token 尚未生效、Token 过期、Token 耗尽、Token 密文无效和并发冲突。

所有失败均 fail closed。HTTP 层将类别映射为状态码，但外部响应不暴露私钥、密码派生信息、完整共享密钥、完整 ACT 明文、注册表内部状态或可用于验签探测的过细差异。结构化日志记录事件名、公开实体 ID、结果类别、耗时和关联 ID；禁止记录密码、私钥、SOTK、SDHK 或 ACT 明文。

以下操作不得部分提交：Agent 注册、OTK 发放、pair budget 扣减、SOTK 消费、Token 使用计数和 Agent 停用。

## 8. 测试与形式化验证

### 8.1 测试层次

1. 密码与序列化单元测试：固定测试向量、确定性编码、签名篡改、X25519 双方一致性、HKDF 域分离、AEAD 密文和 nonce 篡改。
2. 协议状态机测试：User/Agent 注册、唯一性、策略优先级、OTK 生命周期、ACT 签发、合法复用、自然失效和停用。
3. 论文协议覆盖测试：逐项映射 IV-B 至 IV-E 的消息、签名对象和验证动作。
4. 安全测试：覆盖需求 DOCX 列出的 20 类攻击；每个测试在来源矩阵中区分论文直接评估、论文威胁模型推导和工程加固。
5. 网络测试：真实测试 CA、Provider/Agent 服务、mTLS 双向认证、错误证书、超时、中断和重连。
6. 并发测试：OTK 唯一发放、pair budget 和 `q_max` 线性化；专门验证 `q_max=1` 时多个并发请求仅一个成功。

测试不得依赖 `sleep` 判断时间，不得通过删除测试、降低断言或跳过验签获得通过。

### 8.2 ProVerif

`verification/proverif/` 维护两个模型：

- Agent 注册模型：Agent 与 Provider 的注入式认证和可达性；
- Agent 通信模型：ACT 保密性、双方认证和可达性。

查询范围与论文 Appendix D 一致。通过结果不得表述为已形式化证明策略正确性、原子计数、可用性、DoS 防护、恶意 Provider 安全或实现无漏洞。

## 9. 性能实验

基准覆盖：Ed25519 KeyGen/签名/验签、X25519、HKDF、ACT 加解密、Agent 注册、OTK 发放、ACT 生成与验证、不同 `q_max` 的摊销开销、不同 lifetime 的重新授权次数、1/10/100 个 receiving agents 和并发请求吞吐。

每组输出 mean、median、P95、P99、标准差和样本数，同时记录 CPU、内存、OS、Python、依赖版本、预热次数、正式样本数、并发度和配置。结果保存为稳定 schema 的 CSV 与 JSON，并生成基础静态图表。

验收验证以下趋势：

- `q_max` 增大时，每请求授权开销下降；
- lifetime 增大时，固定时间窗口内重新授权次数下降；
- receiving Agent 数量和并发度变化时，吞吐与开销趋势可解释且可重复。

绝对结果与论文作定性或定量对照，偏差必须结合硬件、网络、存储和实现选择解释。回归门禁使用同一环境历史基线的宽松相对阈值，不以论文硬件数值作为跨环境硬阈值。

## 10. 论文歧义与已确定决策

必须在 Phase 0 单独展开以下问题：

1. IV-C Step 7 与 Appendix Figure 8 的 Provider 签名对象排版不一致；采用正文公式。
2. 协议层允许安全签名方案，论文实现章节仅概述 Curve25519/SHA-256；基础复现选择 Ed25519，并标为工程选择。
3. 论文使用抽象 `Enc`，未固定 AEAD、nonce 格式、AAD、HKDF salt/info 或确定性编码；本规格给出明确工程参数。
4. 论文称 ACT 面向任务，但 ACT 元组没有任务字段；不补入 `task_id`。
5. 论文允许 ACT 复用，却未定义应用层重复请求检测；不虚构请求级防重放属性。
6. `q_max` 的持久状态、崩溃恢复和并发线性化未明确；使用 receiving Agent 端原子状态。
7. 策略更新如何影响已经初始化的 pair counter 未明确；采用不恢复已消费额度的确定性规则。
8. 同等具体度规则冲突未定义；更新时拒绝歧义规则集合。
9. 策略更新和停用对已签发 ACT 的语义未完整规定；采用自然过期/耗尽，不实现主动撤销。
10. 外部身份服务、人类验证、公开可路由 IP、网络 DoS 防护和安全注册表是论文假设，不被本地测试替身误报为完整复现。
11. Provider 在核心协议中按规执行但可 honest-but-curious；恶意 Provider、PBFT、RAFT、分片和联邦属于论文扩展，不进入基础实现。
12. 论文形式化证明只覆盖保密性和认证，不能外推为全部安全属性。

## 11. 文档与阶段

Phase 0 产出：

```text
docs/
├── paper-analysis.md
├── architecture.md
├── protocol-messages.md
├── threat-model.md
├── feature-source-matrix.md
├── ambiguities-and-decisions.md
├── experiment-plan.md
└── implementation-plan.md
```

后续阶段：

1. Phase 1：确定性序列化和密码基础。
2. Phase 2：User 与 Agent 注册。
3. Phase 3：Contact Policy、OTK 和并发状态。
4. Phase 4：ACT 生命周期与 `q_max`。
5. Phase 5：FastAPI、真实测试 CA 和 mTLS 端到端协议。
6. Phase 6：攻击实验与 ProVerif。
7. Phase 7：性能趋势实验。
8. Phase 8：复现报告、全量回归和稳定性门禁。

每个阶段先写失败测试，再写最小实现；结束时运行阶段测试和全量回归，并按需求 DOCX 的十项格式汇报。

## 12. Git 与创新分支门禁

Phase 0 初始化 `main` 并只提交分析、设计和计划文档。基础 SAGA 通过全部稳定性门禁后：

1. 生成完整复现报告和功能来源矩阵快照；
2. 创建 `saga-baseline-v1` 标签；
3. 从该标签创建 `feature/agent-tool-authorization`；
4. 工具授权的模型、Token 字段、策略、测试和文档只进入该分支；
5. 基础分支只接受基础 SAGA 的缺陷修复和复现证据更新。

工具授权分支不得把扩展字段回写并宣称为论文原始设计。
