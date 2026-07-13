# Phase 2 Simulated Incident Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Windows 本机交付一个不依赖 LLM 的钓鱼攻击仿真闭环，能够从前端一键完成证据收集、确定性研判、模拟封禁、结果验证和审计。

**Architecture:** 后端采用领域状态机、SQLAlchemy 仓储、状态驱动仿真器和进程内后台运行器；API 创建运行后立即返回，前端每 500 毫秒轮询。原始证据、研判、工具结果和审计相互分离，仿真端口未来可替换为真实安全设备适配器。

**Tech Stack:** Python 3.12–3.14、FastAPI、Pydantic、SQLAlchemy 2、Alembic、SQLite、Pytest、React 19、TypeScript、Vite、Vitest、Testing Library、PowerShell 5.1+。

## Global Constraints

- 阶段二不得调用 DeepSeek、Embedding、Reranker、Milvus 或任何真实安全设备。
- 只实现 `block_ip` 仿真动作；不实现隔离终端、禁用账号、RAG、多智能体、可信工具网关或 ReAct。
- 默认场景使用 `198.51.100.24` 文档示例地址，并在 API 和页面明确标注模拟环境。
- 固定场景数据为事件 `INC-2026-0001`、告警 `ALT-2026-0001`、终端 `PC-023`、用户 `zhangsan`、源地址 `10.10.23.17`、目标 `198.51.100.24:443`、进程 `powershell.exe`、父进程 `WINWORD.EXE`、情报标签 `known-malicious-c2`。
- 默认测试必须强制跳过真实 DeepSeek 测试，不产生付费 API 调用。
- API 使用 `/api/v1`；所有错误继续使用阶段一统一错误结构和请求 ID。
- 所有 ID 使用 UUID；时间以 UTC 存储并使用带时区的 `datetime`。
- 证据创建后不可更新；状态转换和审计必须在同一事务提交。
- 同一场景实例最多一个活动运行；同一幂等键只能对应一个工具执行结果。
- 启动恢复只把遗留的 `collecting`、`analyzing`、`executing`、`verifying` 标记为 `interrupted`，与书面规格保持一致。
- 失败注入只在非生产环境可用，生产环境请求返回 `403`。
- 前端每 500 毫秒轮询；阶段二不引入 SSE、WebSocket、Celery、Redis 或消息队列。
- 本机演示每个已提交步骤之间默认暂停 600 毫秒，测试注入 0；同步工作流必须在线程中运行，不阻塞 FastAPI 事件循环。
- 每个任务遵循 RED→GREEN→REFACTOR，运行聚焦测试、完整回归、Ruff/ESLint/类型检查，并单独提交。

---

## Planned File Structure

```text
backend/src/shieldchain/incidents/
├─ __init__.py
├─ domain.py                  # 枚举、不可变领域值和转换规则
├─ ports.py                   # 仿真、时钟、仓储端口
├─ persistence.py             # SQLAlchemy 持久化模型
├─ repositories.py            # 事务化仓储实现
├─ scenario.py                # 钓鱼场景种子与状态查询
├─ rules.py                   # 确定性研判
├─ tools.py                   # 幂等 block_ip 仿真工具
├─ workflow.py                # 闭环状态机编排
├─ background.py              # 进程内任务与启动恢复
└─ schemas.py                 # API 请求和响应 Schema
backend/src/shieldchain/api/incidents.py
backend/migrations/versions/20260713_01_phase_2_incident_loop.py
backend/tests/unit/incidents/
backend/tests/integration/incidents/
backend/tests/integration/api/test_incidents.py
frontend/src/features/investigation/
├─ api.ts
├─ types.ts
├─ useInvestigation.ts
├─ InvestigationPage.tsx
├─ InvestigationPage.test.tsx
└─ investigation.css
tests/scripts/run-phase2-smoke.ps1
```

---

### Task 1: Incident Domain Types and State Machine

**Files:**
- Create: `backend/src/shieldchain/incidents/__init__.py`
- Create: `backend/src/shieldchain/incidents/domain.py`
- Create: `backend/tests/unit/incidents/test_domain.py`

**Interfaces:**
- Produces: `InvestigationStatus`, `StepStatus`, `Conclusion`, `RiskLevel`, `ToolCallStatus`, `RunMode` string enums.
- Produces: frozen `Evidence`, `Assessment`, `ToolResult`, `VerificationResult`, `PhishingScenarioState`, `BlockOutcome`, `InvestigationRun`, `IncidentDetail`, `AuditEvent` dataclasses.
- Produces: `transition(current: InvestigationStatus, target: InvestigationStatus) -> InvestigationStatus`.
- Produces: `is_terminal(status: InvestigationStatus) -> bool` and `is_active(status: InvestigationStatus) -> bool`.

- [ ] **Step 1: Write failing enum, immutability and transition tests**

```python
def test_happy_path_transitions_are_explicit() -> None:
    status = InvestigationStatus.PENDING
    for target in (
        InvestigationStatus.COLLECTING,
        InvestigationStatus.ANALYZING,
        InvestigationStatus.ACTION_PLANNED,
        InvestigationStatus.EXECUTING,
        InvestigationStatus.VERIFYING,
        InvestigationStatus.CLOSED,
    ):
        status = transition(status, target)
    assert status is InvestigationStatus.CLOSED


def test_closed_cannot_transition_back_to_executing() -> None:
    with pytest.raises(InvalidInvestigationTransition):
        transition(InvestigationStatus.CLOSED, InvestigationStatus.EXECUTING)


def test_evidence_is_immutable() -> None:
    evidence = make_evidence()
    with pytest.raises(FrozenInstanceError):
        evidence.summary = "changed"
```

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/incidents/test_domain.py -v`

Expected: collection fails because `shieldchain.incidents.domain` does not exist.

- [ ] **Step 3: Implement exact enums, dataclasses and transition map**

```python
class InvestigationStatus(StrEnum):
    PENDING = "pending"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    ACTION_PLANNED = "action_planned"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    CLOSED = "closed"

class Conclusion(StrEnum):
    CONFIRMED_THREAT = "confirmed_threat"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

class RiskLevel(StrEnum):
    HIGH = "high"
    UNKNOWN = "unknown"

class ToolCallStatus(StrEnum):
    BLOCKED = "blocked"
    ALREADY_BLOCKED = "already_blocked"
    FAILED = "failed"

class RunMode(StrEnum):
    NORMAL = "normal"
    FAIL_BLOCK_ONCE = "fail_block_once"


ALLOWED_TRANSITIONS = {
    InvestigationStatus.PENDING: {InvestigationStatus.COLLECTING},
    InvestigationStatus.COLLECTING: {
        InvestigationStatus.ANALYZING,
        InvestigationStatus.NEEDS_REVIEW,
        InvestigationStatus.INTERRUPTED,
    },
    InvestigationStatus.ANALYZING: {
        InvestigationStatus.ACTION_PLANNED,
        InvestigationStatus.NEEDS_REVIEW,
        InvestigationStatus.INTERRUPTED,
    },
    InvestigationStatus.ACTION_PLANNED: {
        InvestigationStatus.EXECUTING,
        InvestigationStatus.INTERRUPTED,
    },
    InvestigationStatus.EXECUTING: {
        InvestigationStatus.VERIFYING,
        InvestigationStatus.FAILED,
        InvestigationStatus.INTERRUPTED,
    },
    InvestigationStatus.VERIFYING: {
        InvestigationStatus.CLOSED,
        InvestigationStatus.FAILED,
        InvestigationStatus.INTERRUPTED,
    },
}
```

`Evidence` must include UUID ID, type, source, observed UTC time, summary, raw reference, SHA-256 integrity hash, confidence from 0 to 1, confirmed flag. Reject naive datetimes, invalid confidence and empty references in `__post_init__`.

Use these exact value-object fields so later tasks share one contract:

```python
@dataclass(frozen=True, slots=True)
class Assessment:
    conclusion: Conclusion
    risk_level: RiskLevel
    rule_ids: tuple[str, ...]
    evidence_ids: tuple[UUID, ...]
    recommended_action: str | None
    explanation: str

@dataclass(frozen=True, slots=True)
class ToolResult:
    status: ToolCallStatus
    tool_name: str
    target: str
    idempotency_key: str
    before_state: Mapping[str, str]
    after_state: Mapping[str, str]
    error_code: str | None = None

@dataclass(frozen=True, slots=True)
class VerificationResult:
    blocked: bool
    connection_stopped: bool
    observed_at: datetime
    evidence_ids: tuple[UUID, ...]
```

- [ ] **Step 4: Run GREEN and backend regression**

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/incidents/test_domain.py -v
.\.venv\Scripts\python -m pytest backend/tests -q
.\.venv\Scripts\python -m ruff check backend
```

Expected: focused tests pass; existing 54 tests pass with one guarded live skip; Ruff passes.

- [ ] **Step 5: Update development log and commit**

```powershell
git add backend/src/shieldchain/incidents backend/tests/unit/incidents development-logs
git commit -m "feat: add incident domain state machine"
```

---

### Task 2: Incident Persistence Schema and Alembic Migration

**Files:**
- Create: `backend/src/shieldchain/incidents/persistence.py`
- Create: `backend/migrations/versions/20260713_01_phase_2_incident_loop.py`
- Create: `backend/tests/unit/incidents/test_persistence.py`
- Modify: `backend/src/shieldchain/db/base.py`

**Interfaces:**
- Produces SQLAlchemy models: `SimulationInstanceRow`, `IncidentRow`, `InvestigationRunRow`, `InvestigationStepRow`, `EvidenceRecordRow`, `SimulationToolCallRow`, `AuditEventRow`.
- Produces one migration whose `upgrade()` creates all seven tables and whose `downgrade()` drops them in reverse dependency order.
- `simulation_instances` is the source of truth for mutable simulated firewall/connection state; `simulation_tool_calls` stores the immutable first result for each idempotency key.

- [ ] **Step 1: Write failing metadata constraint tests**

```python
def test_phase_two_tables_are_registered() -> None:
    assert {
        "simulation_instances", "incidents", "investigation_runs",
        "investigation_steps", "evidence_records",
        "simulation_tool_calls", "audit_events",
    }.issubset(Base.metadata.tables)


def test_active_run_and_idempotency_constraints_exist() -> None:
    tool_table = Base.metadata.tables["simulation_tool_calls"]
    assert any(
        isinstance(c, UniqueConstraint)
        and c.name == "uq_tool_call_idempotency_key"
        for c in tool_table.constraints
    )
```

Also test foreign keys, non-null UTC timestamps, evidence payload columns and a partial unique SQLite index preventing more than one active run per simulation instance.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/incidents/test_persistence.py -v`

Expected: FAIL because persistence models and tables are absent.

- [ ] **Step 3: Implement focused SQLAlchemy models**

Store UUIDs as 36-character strings for SQLite portability. Store enums as validated strings, structured evidence/tool/audit data as JSON, and timestamps as timezone-aware `DateTime(timezone=True)`. Use this active-status index predicate:

```python
ACTIVE_VALUES = ("pending", "collecting", "analyzing", "action_planned", "executing", "verifying")

Index(
    "uq_active_run_per_simulation",
    InvestigationRunRow.simulation_instance_id,
    unique=True,
    sqlite_where=InvestigationRunRow.status.in_(ACTIVE_VALUES),
)
```

The model columns must cover these exact persisted contracts:

```python
# simulation_instances
id, scenario_key, generation, environment, connection_status,
firewall_status, fail_block_consumed, created_at, updated_at

# incidents
id, external_id, simulation_instance_id, alert_id, endpoint,
username, source_ip, remote_ip, remote_port, process_name,
parent_process_name, threat_label, created_at

# investigation_runs
id, incident_id, simulation_instance_id, status, mode,
assessment_json, verification_json, created_at, updated_at, completed_at

# investigation_steps / evidence_records / simulation_tool_calls / audit_events
# Each row includes its owning run or incident ID, UUID primary key, UTC timestamp,
# status/type fields, and JSON payload needed by the API without recomputation.
```

- [ ] **Step 4: Generate and inspect one migration**

Run: `.\.venv\Scripts\alembic -c backend/alembic.ini revision --autogenerate --rev-id 20260713_01 -m "phase 2 incident loop"`

Expected: one new migration file. Inspect it to ensure it includes all tables, foreign keys, unique constraints and the partial active-run index; remove unrelated changes if autogenerate includes them.

- [ ] **Step 5: Verify migration round trip in a temporary SQLite database**

Run a test that applies `upgrade head`, asserts the seven tables, applies `downgrade -1`, and asserts their removal. Then run:

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/incidents/test_persistence.py -v
.\.venv\Scripts\python -m pytest backend/tests -q
.\.venv\Scripts\python -m ruff check backend
```

- [ ] **Step 6: Update log and commit**

```powershell
git add backend/src/shieldchain/db/base.py backend/src/shieldchain/incidents/persistence.py backend/migrations backend/tests/unit/incidents development-logs
git commit -m "feat: add incident persistence schema"
```

---

### Task 3: Transactional Incident Repository

**Files:**
- Create: `backend/src/shieldchain/incidents/ports.py`
- Create: `backend/src/shieldchain/incidents/repositories.py`
- Create: `backend/tests/integration/incidents/test_repositories.py`

**Interfaces:**
- Produces `IncidentRepository` protocol and `SqlAlchemyIncidentRepository`.
- Produces the exact protocol below; `apply_tool_outcome()` atomically writes simulated state and the immutable tool result.
- Each mutating method consumes one caller-owned `Session`; repository methods flush but do not commit independently.

```python
class IncidentRepository(Protocol):
    def reset_phishing_scenario(self, session: Session, *, now: datetime) -> PhishingScenarioState: ...
    def create_run(self, session: Session, *, simulation_id: UUID, mode: RunMode,
                   request_id: str, now: datetime) -> InvestigationRun: ...
    def get_run(self, session: Session, run_id: UUID) -> InvestigationRun | None: ...
    def get_simulation(self, session: Session, simulation_id: UUID) -> PhishingScenarioState | None: ...
    def transition_run(self, session: Session, run_id: UUID, target: InvestigationStatus,
                       *, request_id: str, now: datetime) -> InvestigationRun: ...
    def append_evidence(self, session: Session, run_id: UUID,
                        evidence: Sequence[Evidence], *, request_id: str) -> None: ...
    def save_assessment(self, session: Session, run_id: UUID, assessment: Assessment,
                        *, request_id: str, now: datetime) -> None: ...
    def get_tool_result(self, session: Session, idempotency_key: str) -> ToolResult | None: ...
    def apply_tool_outcome(self, session: Session, run_id: UUID, outcome: BlockOutcome,
                           *, request_id: str, now: datetime) -> ToolResult: ...
    def save_verification(self, session: Session, run_id: UUID,
                          result: VerificationResult, *, request_id: str) -> None: ...
    def get_incident(self, session: Session, incident_id: UUID) -> IncidentDetail | None: ...
    def list_audit(self, session: Session, incident_id: UUID) -> Sequence[AuditEvent]: ...
    def mark_recoverable_runs_interrupted(self, session: Session, *, request_id: str,
                                          now: datetime) -> int: ...
```

- [ ] **Step 1: Write failing transaction, append-only and concurrency tests**

```python
def test_transition_and_audit_commit_atomically(session, repository) -> None:
    run = repository.create_run(session, simulation_id=SIM_ID)
    repository.transition_run(session, run.id, InvestigationStatus.COLLECTING, request_id="req-1")
    session.commit()
    assert repository.get_run(session, run.id).status == "collecting"
    assert [event.event_type for event in repository.list_audit(session, run.incident_id)] == [
        "run_created", "status_changed"
    ]


def test_second_active_run_is_rejected(session, repository) -> None:
    repository.create_run(session, simulation_id=SIM_ID)
    session.commit()
    with pytest.raises(ActiveInvestigationExists):
        repository.create_run(session, simulation_id=SIM_ID)
```

Also prove duplicate evidence IDs and idempotency keys are rejected, evidence has no update method, reset refuses active runs, and rollback removes both status and audit changes.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python -m pytest backend/tests/integration/incidents/test_repositories.py -v`

Expected: collection fails because repository ports are missing.

- [ ] **Step 3: Implement protocol and SQLAlchemy repository**

Map `IntegrityError` deterministically to `ActiveInvestigationExists` or `DuplicateIdempotencyKey` without exposing SQL. Use explicit `select()` queries and `with_for_update()` where supported; SQLite correctness relies on the database unique index plus transaction rollback.

- [ ] **Step 4: Run focused and full tests**

```powershell
.\.venv\Scripts\python -m pytest backend/tests/integration/incidents/test_repositories.py -v
.\.venv\Scripts\python -m pytest backend/tests -q
.\.venv\Scripts\python -m ruff check backend
```

- [ ] **Step 5: Update log and commit**

```powershell
git add backend/src/shieldchain/incidents/ports.py backend/src/shieldchain/incidents/repositories.py backend/tests/integration/incidents development-logs
git commit -m "feat: add transactional incident repository"
```

---

### Task 4: State-Driven Phishing Simulator, Rules, and Idempotent Tool

**Files:**
- Create: `backend/src/shieldchain/incidents/scenario.py`
- Create: `backend/src/shieldchain/incidents/rules.py`
- Create: `backend/src/shieldchain/incidents/tools.py`
- Create: `backend/tests/unit/incidents/test_scenario.py`
- Create: `backend/tests/unit/incidents/test_rules.py`
- Create: `backend/tests/unit/incidents/test_tools.py`

**Interfaces:**
- Consumes `PhishingScenarioState` and `BlockOutcome` from Task 1; it does not introduce a second simulation-state type.
- Produces `seed_phishing_scenario(now: datetime) -> PhishingScenarioState`.
- Produces `collect_evidence(state: PhishingScenarioState, now: datetime) -> tuple[Evidence, ...]`.
- Produces `assess(evidence: tuple[Evidence, ...]) -> Assessment`.
- Produces `SimulatedFirewall.block_ip(state, ip, idempotency_key, fail_once=False) -> BlockOutcome`; it returns a new snapshot and does not persist.
- Produces `verify_block(state, ip, now) -> VerificationResult`.

- [ ] **Step 1: Write failing seed, rule, idempotency and failure tests**

```python
def test_seed_uses_safe_documentation_ip() -> None:
    state = seed_phishing_scenario(NOW)
    assert state.remote_ip == ip_address("198.51.100.24")
    assert state.connection_status == "active"
    assert state.firewall_status == "not_blocked"


def test_assessment_requires_all_evidence() -> None:
    evidence = collect_evidence(seed_phishing_scenario(NOW), NOW)
    assert assess(evidence).conclusion is Conclusion.CONFIRMED_THREAT
    assert assess(evidence[:-1]).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_fail_once_does_not_change_simulation_state() -> None:
    state = seed_phishing_scenario(NOW)
    outcome = SimulatedFirewall().block_ip(state, state.remote_ip, "key-1", fail_once=True)
    assert outcome.result.status is ToolCallStatus.FAILED
    assert outcome.state.firewall_status == "not_blocked"
    assert outcome.state.connection_status == "active"
    assert outcome.state.fail_block_consumed is True
```

Also test a new key against an already blocked IP returns `already_blocked`, and read-only collection does not mutate state. Persistent repetition of the same idempotency key is tested through the Task 3 repository and Task 5 workflow.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python -m pytest backend/tests/unit/incidents/test_scenario.py backend/tests/unit/incidents/test_rules.py backend/tests/unit/incidents/test_tools.py -v`

Expected: missing modules during collection.

- [ ] **Step 3: Implement immutable scenario values and controlled mutable state**

Use immutable snapshots and this exact transition boundary. Compute evidence integrity hash from canonical JSON with sorted keys and UTF-8 SHA-256. Rules reference exact evidence IDs and emit rule IDs `PHISH-001` through `PHISH-005`.

```python
@dataclass(frozen=True, slots=True)
class PhishingScenarioState:
    simulation_id: UUID
    incident_id: UUID
    external_incident_id: str
    alert_id: str
    endpoint: str
    username: str
    source_ip: IPv4Address
    alert_status: str
    remote_ip: IPv4Address
    remote_port: int
    process_name: str
    parent_process_name: str
    threat_label: str
    connection_status: str
    firewall_status: str
    fail_block_consumed: bool

@dataclass(frozen=True, slots=True)
class BlockOutcome:
    state: PhishingScenarioState
    result: ToolResult

def block_ip(self, state: PhishingScenarioState, ip: IPv4Address,
             idempotency_key: str, *, fail_once: bool = False) -> BlockOutcome:
    if ip != state.remote_ip:
        raise InvalidSimulationTarget(str(ip))
    before = state_view(state)
    if fail_once and not state.fail_block_consumed:
        consumed = replace(state, fail_block_consumed=True)
        return BlockOutcome(
            state=consumed,
            result=failed_result(ip, idempotency_key, before, state_view(consumed)),
        )
    if state.firewall_status == "blocked":
        return BlockOutcome(
            state=state,
            result=already_blocked_result(ip, idempotency_key, before),
        )
    blocked = replace(
        state, connection_status="blocked", firewall_status="blocked"
    )
    return BlockOutcome(
        state=blocked,
        result=blocked_result(ip, idempotency_key, before, state_view(blocked)),
    )
```

- [ ] **Step 4: Run focused/full verification**

```powershell
.\.venv\Scripts\python -m pytest backend/tests/unit/incidents/test_scenario.py backend/tests/unit/incidents/test_rules.py backend/tests/unit/incidents/test_tools.py -v
.\.venv\Scripts\python -m pytest backend/tests -q
.\.venv\Scripts\python -m ruff check backend
```

- [ ] **Step 5: Update log and commit**

```powershell
git add backend/src/shieldchain/incidents backend/tests/unit/incidents development-logs
git commit -m "feat: add phishing simulation and deterministic rules"
```

---

### Task 5: Deterministic Investigation Workflow

**Files:**
- Create: `backend/src/shieldchain/incidents/workflow.py`
- Create: `backend/tests/integration/incidents/test_workflow.py`

**Interfaces:**
- Produces `InvestigationWorkflow(repository, firewall, clock, sleeper, step_delay_seconds)`; production uses 0.6 seconds and tests use 0.
- Produces `run(session_factory, run_id: UUID, *, request_id: str, fail_block_once: bool=False) -> InvestigationStatus`.
- Consumes Task 3 repository and Task 4 simulator/rules/tool ports.

- [ ] **Step 1: Write failing happy, insufficient, failed and already-closed tests**

```python
def test_workflow_closes_only_after_verified_state(workflow, repository) -> None:
    run_id = create_default_run(repository)
    assert workflow.run(session_factory, run_id) is InvestigationStatus.CLOSED
    run = load_run(run_id)
    assert run.status == "closed"
    assert load_simulation(run.simulation_instance_id).connection_status == "blocked"
    assert_is_ordered_subsequence(audit_types(run.incident_id), [
        "run_created", "evidence_collected", "assessment_completed",
        "tool_called", "verification_completed",
    ])
    assert recorded_statuses(run_id) == [
        "pending", "collecting", "analyzing", "action_planned",
        "executing", "verifying", "closed",
    ]


def test_tool_failure_never_records_closed(workflow) -> None:
    run_id = create_default_run()
    assert workflow.run(session_factory, run_id, fail_block_once=True) is InvestigationStatus.FAILED
    assert load_simulation_for_run(run_id).connection_status == "active"
    assert "closed" not in recorded_statuses(run_id)
```

Also test insufficient evidence reaches `needs_review` without a tool row, already closed returns existing result, every step is persisted, and an exception rolls back its current transaction before recording a sanitized failure in a new transaction.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python -m pytest backend/tests/integration/incidents/test_workflow.py -v`

Expected: missing `InvestigationWorkflow`.

- [ ] **Step 3: Implement one explicit method per workflow step**

`run()` must call `_collect`, `_analyze`, `_execute`, `_verify` in order. Each helper opens a short transaction, validates the current status, persists the step and audit together, then commits. `_execute` first loads an existing idempotent result; otherwise it computes `BlockOutcome` and calls `apply_tool_outcome()` so state and result commit atomically. Do not use recursive retries or model-driven routing.

```python
def run(self, session_factory: sessionmaker[Session], run_id: UUID, *,
        request_id: str, fail_block_once: bool = False) -> InvestigationStatus:
    run = self._load_run(session_factory, run_id)
    if is_terminal(run.status):
        return run.status
    self._collect(session_factory, run_id, request_id=request_id)
    self._pause()
    assessment = self._analyze(session_factory, run_id, request_id=request_id)
    if assessment.conclusion is Conclusion.INSUFFICIENT_EVIDENCE:
        return InvestigationStatus.NEEDS_REVIEW
    self._pause()
    self._execute(session_factory, run_id, request_id=request_id,
                  fail_block_once=fail_block_once)
    self._pause()
    return self._verify(session_factory, run_id, request_id=request_id)
```

- [ ] **Step 4: Run focused/full verification**

```powershell
.\.venv\Scripts\python -m pytest backend/tests/integration/incidents/test_workflow.py -v
.\.venv\Scripts\python -m pytest backend/tests -q
.\.venv\Scripts\python -m ruff check backend
```

- [ ] **Step 5: Update log and commit**

```powershell
git add backend/src/shieldchain/incidents/workflow.py backend/tests/integration/incidents/test_workflow.py development-logs
git commit -m "feat: add deterministic investigation workflow"
```

---

### Task 6: Incident API, Background Runner, and Restart Recovery

**Files:**
- Create: `backend/src/shieldchain/incidents/schemas.py`
- Create: `backend/src/shieldchain/incidents/background.py`
- Create: `backend/src/shieldchain/api/incidents.py`
- Modify: `backend/src/shieldchain/core/config.py`
- Modify: `backend/src/shieldchain/main.py`
- Create: `backend/tests/integration/api/test_incidents.py`
- Create: `backend/tests/integration/incidents/test_background.py`

**Interfaces:**
- Produces exactly these five APIs:
  - `POST /api/v1/simulations/phishing/reset`
  - `POST /api/v1/investigations`
  - `GET /api/v1/investigations/{run_id}`
  - `GET /api/v1/incidents/{incident_id}`
  - `GET /api/v1/incidents/{incident_id}/audit`
- Produces `InvestigationRunner.start(run_id, request_id, fail_block_once=False) -> None`, `shutdown()`, and `recover_interrupted() -> int`.
- Startup lifespan calls `recover_interrupted`; shutdown stops accepting tasks and awaits active tasks within a bounded timeout.
- Runner launches the synchronous SQLAlchemy workflow with `asyncio.to_thread`; it never executes the workflow directly on the event loop.

- [ ] **Step 1: Write failing API contract and recovery tests**

```python
def test_start_returns_run_without_waiting(client, seeded_simulation) -> None:
    response = client.post("/api/v1/investigations", json={
        "simulation_instance_id": str(seeded_simulation.id),
        "mode": "normal",
    })
    assert response.status_code == 202
    assert response.json()["status"] == "pending"


def test_production_rejects_failure_injection(production_client, seeded_simulation) -> None:
    response = production_client.post("/api/v1/investigations", json={
        "simulation_instance_id": str(seeded_simulation.id),
        "mode": "fail_block_once",
    })
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "simulation_mode_forbidden"


def test_startup_marks_active_runs_interrupted(app_factory) -> None:
    run_ids = seed_runs_in_statuses({"collecting", "analyzing", "executing", "verifying"})
    with TestClient(app_factory()):
        pass
    assert {load_status(run_id) for run_id in run_ids} == {"interrupted"}
```

Also test reset, incident detail, audit ordering, 404/409 errors, active-run concurrency, reset rejection while active, polling to terminal state and request IDs on every response.

- [ ] **Step 2: Run RED**

Run: `.\.venv\Scripts\python -m pytest backend/tests/integration/api/test_incidents.py backend/tests/integration/incidents/test_background.py -v`

Expected: incident router and runner imports fail.

- [ ] **Step 3: Implement strict Pydantic schemas and runner**

Use `Literal["normal", "fail_block_once"]` for mode and UUID types for IDs. API clients cannot supply IPs, tool names, rule IDs or commands. Map domain exceptions to `ApiError` codes `simulation_not_found`, `investigation_already_running`, `invalid_investigation_state`, and `simulation_mode_forbidden`.

```python
class StartInvestigationRequest(BaseModel):
    simulation_instance_id: UUID
    mode: Literal["normal", "fail_block_once"] = "normal"

@router.post("/investigations", status_code=202, response_model=InvestigationResponse)
def start_investigation(payload: StartInvestigationRequest,
                        request_id: RequestIdDep,
                        services: IncidentServicesDep) -> InvestigationResponse:
    run = services.create_run(payload, request_id=request_id)
    services.runner.start(run.id, request_id, payload.mode == "fail_block_once")
    return services.presenter.investigation(run.id)
```

Add `SIMULATION_STEP_DELAY_MS` to settings with default `600` and inclusive range `0..2000`. Construct the workflow with `settings.simulation_step_delay_ms / 1000`. In tests, inject `0`; do not make the test suite sleep.

```python
task = asyncio.create_task(asyncio.to_thread(
    self._workflow.run,
    self._session_factory,
    run_id,
    request_id=request_id,
    fail_block_once=fail_block_once,
))
self._tasks.add(task)
task.add_done_callback(self._tasks.discard)
```

- [ ] **Step 4: Register router and lifespan without breaking health checks**

`create_app()` must accept injectable repository/runner dependencies for tests. Keep `/api/v1/health/live` and readiness contracts unchanged.

- [ ] **Step 5: Run focused/full verification**

```powershell
.\.venv\Scripts\python -m pytest backend/tests/integration/api/test_incidents.py backend/tests/integration/incidents/test_background.py -v
.\.venv\Scripts\python -m pytest backend/tests -q
.\.venv\Scripts\python -m ruff check backend
.\.venv\Scripts\alembic -c backend/alembic.ini upgrade head
```

- [ ] **Step 6: Update log and commit**

```powershell
git add backend/src/shieldchain backend/tests backend/migrations development-logs
git commit -m "feat: expose simulated investigation API"
```

---

### Task 7: Minimal Incident Investigation Page

**Files:**
- Create: `frontend/src/features/investigation/types.ts`
- Create: `frontend/src/features/investigation/api.ts`
- Create: `frontend/src/features/investigation/useInvestigation.ts`
- Create: `frontend/src/features/investigation/InvestigationPage.tsx`
- Create: `frontend/src/features/investigation/InvestigationPage.test.tsx`
- Create: `frontend/src/features/investigation/investigation.css`
- Modify: `frontend/src/app/router.tsx`
- Modify: `frontend/src/app/App.test.tsx`

**Interfaces:**
- Produces `resetPhishingScenario()`, `startInvestigation()`, `getInvestigation()`, `getIncident()`, `getAudit()` typed API functions.
- Produces `useInvestigation()` polling hook with 500 ms interval, abort cleanup and terminal-state stop.
- Replaces only the `/events` future page with `InvestigationPage`; other future routes remain unchanged.

```ts
export type InvestigationStatus =
  | 'pending' | 'collecting' | 'analyzing' | 'action_planned'
  | 'executing' | 'verifying' | 'needs_review' | 'failed'
  | 'interrupted' | 'closed'

export interface InvestigationResponse {
  run_id: string
  incident_id: string
  status: InvestigationStatus
  simulation: {connection_status: string; firewall_status: string}
  steps: InvestigationStep[]
  evidence: EvidenceView[]
  assessment: AssessmentView | null
  toolResult: ToolResultView | null
  verification: VerificationView | null
}
```

- [ ] **Step 1: Write failing typed client and page tests**

```tsx
it('runs the default simulation to a verified closed result', async () => {
  vi.useFakeTimers()
  mockResetAndInvestigationSequence(['pending', 'collecting', 'executing', 'verifying', 'closed'])
  render(<InvestigationPage />)
  await userEvent.click(screen.getByRole('button', {name: '启动调查'}))
  await vi.advanceTimersByTimeAsync(2000)
  expect(await screen.findByText('已闭环')).toBeInTheDocument()
  expect(screen.getByText('198.51.100.24')).toBeInTheDocument()
  expect(screen.getByText('连接已停止')).toBeInTheDocument()
})


it('shows tool failure without a false success state', async () => {
  renderFailureModePage()
  expect(await screen.findByText('处置失败')).toBeInTheDocument()
  expect(screen.queryByText('已闭环')).not.toBeInTheDocument()
})
```

Also test simulation badge, 500 ms polling, stop on all four terminal states, retry after polling error, reset, buttons disabled while active, production hiding/disabling failure mode, evidence and audit rendering, and abort on unmount.

- [ ] **Step 2: Run RED**

Run: `npm.cmd test --prefix frontend -- --run src/features/investigation/InvestigationPage.test.tsx`

Expected: missing page and client modules.

- [ ] **Step 3: Implement typed client and polling hook**

Reuse the phase-one abort/timeout patterns. Parse only expected response shapes; unexpected status or body raises a public `InvestigationApiError`. Poll exactly every 500 ms and cancel the timer plus request on unmount or reset.

```ts
const TERMINAL = new Set<InvestigationStatus>([
  'closed', 'failed', 'needs_review', 'interrupted',
])

useEffect(() => {
  if (!runId || !run || TERMINAL.has(run.status)) return
  const controller = new AbortController()
  const timer = window.setTimeout(() => refresh(controller.signal), 500)
  return () => { controller.abort(); window.clearTimeout(timer) }
}, [runId, run?.status, refresh])
```

- [ ] **Step 4: Implement accessible page and route**

Use semantic headings, ordered timeline, status text plus color, native buttons and existing design tokens. Do not render hidden chain-of-thought labels. Show evidence source, summary, confidence, integrity status, tool target, idempotency key, before/after state and final result.

- [ ] **Step 5: Run frontend gates**

```powershell
npm.cmd test --prefix frontend -- --run
npm.cmd run lint --prefix frontend
npm.cmd run typecheck --prefix frontend
npm.cmd run build --prefix frontend
```

Expected: all tests, lint, typecheck and build pass.

- [ ] **Step 6: Update log and commit**

```powershell
git add frontend development-logs
git commit -m "feat: add simulated incident investigation page"
```

---

### Task 8: Windows End-to-End Gate and Phase 2 Documentation

**Files:**
- Create: `tests/scripts/run-phase2-smoke.ps1`
- Modify: `tests/scripts/run-contract-tests.ps1`
- Modify: `scripts/verify.ps1`
- Modify: `README.md`
- Modify: `docs/operations/local-development.md`
- Modify: `docs/plans/development-roadmap.md`
- Modify: `development-logs/2026-07-13.md`

**Interfaces:**
- Produces a deterministic Phase 2 smoke command that uses a temporary SQLite database and cleans processes/data.
- Adds Phase 2 smoke to the full verification gate after existing backend/frontend checks.

- [ ] **Step 1: Write a failing Phase 2 smoke contract**

The PowerShell test must start the real backend and frontend, call reset through the frontend origin, start a normal investigation, poll with a bounded 30-second deadline, and assert:

```powershell
$final.status | Should-Be 'closed'
$final.simulation.connection_status | Should-Be 'blocked'
$final.simulation.firewall_status | Should-Be 'blocked'
$audit.event_types | Should-Contain 'evidence_collected'
$audit.event_types | Should-Contain 'tool_called'
$audit.event_types | Should-Contain 'verification_completed'
```

Use the existing Pester-free assertion style rather than downloading Pester.

- [ ] **Step 2: Run RED**

Run: `powershell -ExecutionPolicy Bypass -File tests/scripts/run-phase2-smoke.ps1`

Expected: FAIL because the smoke script or documented setup is incomplete before Task 8 implementation.

- [ ] **Step 3: Implement bounded smoke setup and cleanup**

Create a temporary `.env` only when one does not exist, point `DATABASE_URL` to a temp database, run Alembic upgrade, start both processes, exercise the frontend-origin API, stop both processes in `finally`, remove only files created by the script, and verify ports 8000/5173 are no longer listening.

- [ ] **Step 4: Update exact documentation**

Document migration, reset/start flow, normal and failure modes, the “模拟环境” limitation, phase-two smoke command and troubleshooting. Mark Phase 2 complete in the roadmap only after the complete gate passes.

- [ ] **Step 5: Run the complete phase gate**

```powershell
powershell -ExecutionPolicy Bypass -File tests/scripts/run-contract-tests.ps1
powershell -ExecutionPolicy Bypass -File tests/scripts/run-phase2-smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts/test.ps1
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
git diff --check
git status --short
```

Expected: all commands exit 0; live DeepSeek remains skipped; no `.env`, temp database, process or port remains; status shows only intended Task 8 files before commit.

- [ ] **Step 6: Run security and scope scans**

Verify no real credential patterns, no Shell execution path from API input, no RAG/multi-agent/real-device implementation, and no tracked runtime data or `.superpowers` state.

- [ ] **Step 7: Update log and commit**

```powershell
git add tests/scripts scripts README.md docs development-logs
git commit -m "docs: complete phase two incident loop gate"
git status --short
```

Expected: commit succeeds and worktree is clean.

---

## Phase 2 Exit Review

Phase 2 is accepted only with fresh evidence for every item:

- Default phishing simulation reaches `closed` from the browser-facing flow.
- Firewall and connection state both change to `blocked` before closure.
- Evidence is immutable and references deterministic hashes.
- Insufficient evidence reaches `needs_review` and creates no tool call.
- Failure injection reaches `failed`, preserves active connection state and never reports success.
- Duplicate starts and resets during active runs return stable 409 errors.
- Duplicate tool calls are idempotent.
- Startup marks orphaned active runs `interrupted`.
- Every status transition, evidence collection, tool call and verification has an ordered audit event and request ID.
- Production rejects failure injection.
- Frontend polling cleans timers and requests and stops on all terminal states.
- Alembic upgrade/downgrade, backend tests, frontend tests, PowerShell contracts, Phase 2 smoke, linters, type checks and build pass.
- Default verification makes no paid DeepSeek call.
- Documentation and execution-date log match verified behavior.

After acceptance, write a separate design and implementation plan for Phase 3 product-grade RAG. Do not implement Phase 3 from this plan.
