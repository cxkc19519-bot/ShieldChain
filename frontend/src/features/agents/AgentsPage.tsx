import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { EmptyState, LoadingState } from '../../components/ui/States'
import { PageHeader } from '../../components/ui/PageHeader'
import { StatusBadge } from '../../components/ui/StatusBadge'
import { getMcpRunCalls } from '../mcp/api'
import type { McpRunCall } from '../mcp/types'
import { getCollaborationTrajectory, listAgentRuns } from './api'
import type { AgentRunOption } from './api'
import { controlReactLoop, getReactTrajectory } from './reactApi'
import type { ReactTrajectory } from './reactTypes'
import type { CollaborationTrajectory } from './types'
import './agents.css'

interface LoadIssue {
  kind: 'missing' | 'error'
  message: string
}

const ROLE_LABELS: Record<string, string> = {
  superagent: '总控智能体',
  alert_triage: '告警分诊智能体',
  threat_investigation: '威胁研判智能体',
  knowledge_retrieval: '知识检索智能体',
  response_planning: '响应规划智能体',
  verification: '验证智能体',
  reporting: '报告智能体',
}

const STATUS_LABELS: Record<string, string> = {
  pending: '等待调查', collecting: '收集证据', analyzing: '研判中',
  action_planned: '已生成方案', executing: '执行中', verifying: '验证中',
  closed: '已闭环', failed: '失败', needs_review: '需要复核',
  interrupted: '已中断', completed: '已完成', not_started: '未启动',
}

function roleLabel(value: string): string { return ROLE_LABELS[value] ?? value }
function statusLabel(value: string): string { return STATUS_LABELS[value] ?? value }
function dateTime(value: string): string {
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false })
}

function Metric({ label, used, limit }: { label: string; used: number; limit: number }) {
  return <div className="agent-metric"><span>{label}</span><strong>{used} / {limit}</strong></div>
}

function loadIssue(value: unknown, source: 'collaboration' | 'react' | 'mcp'): LoadIssue {
  const message = value instanceof Error ? value.message : ''
  if (message === 'Agent trajectory not found') return { kind: 'missing', message: '该运行没有生成多智能体协作轨迹。' }
  if (message === 'ReAct trajectory not found') return { kind: 'missing', message: '该运行没有启动 ReAct 循环，因此没有 ReAct 轨迹。' }
  const fallback = source === 'collaboration'
    ? '协作轨迹加载失败，请稍后重试。'
    : source === 'react' ? 'ReAct 轨迹加载失败，请稍后重试。' : 'MCP 调用记录加载失败，请稍后重试。'
  return { kind: 'error', message: /[\u4e00-\u9fff]/.test(message) ? message : fallback }
}

function Collaboration({ trajectory }: { trajectory: CollaborationTrajectory }) {
  return <div className="agent-workspace collaboration-workspace">
    <header><div><span className="agent-phase">{statusLabel(trajectory.phase)}</span><h3>{trajectory.shared_summary}</h3></div><small>修订 {trajectory.revision}</small></header>
    <section aria-labelledby="budget-title"><h3 id="budget-title">协作预算</h3><div className="agent-metrics"><Metric label="步骤" used={trajectory.budget.steps_used} limit={trajectory.budget.step_limit} /><Metric label="Token" used={trajectory.budget.tokens_used} limit={trajectory.budget.token_limit} /><Metric label="工具调用" used={trajectory.budget.tool_calls_used} limit={trajectory.budget.tool_call_limit} /></div></section>
    <section aria-labelledby="handoff-flow-title" className="agent-handoff-flow">
      <div className="agent-section-heading"><div><h3 id="handoff-flow-title">真实协作路线</h3><p>仅按服务端保存的角色交接记录展示，不推测或补画未发生的阶段。</p></div><span>{trajectory.handoffs.length} 次交接</span></div>
      {trajectory.handoffs.length === 0 ? <p className="agent-empty-note">该运行没有角色交接记录。</p> : <ol>{trajectory.handoffs.map((item, index) => <li key={item.id}>
        <span className="agent-flow-index">{index + 1}</span>
        <div className="agent-flow-card">
          <div className="agent-flow-roles"><strong>{roleLabel(item.sender)}</strong><span aria-hidden="true">→</span><strong>{roleLabel(item.receiver)}</strong></div>
          <p>{item.conclusion}</p>
          {item.open_questions.length > 0 && <small>待补证：{item.open_questions.join('、')}</small>}
          <div className="agent-flow-meta"><span>置信度 {Math.round(item.confidence * 100)}%</span><time dateTime={item.created_at}>{dateTime(item.created_at)}</time></div>
        </div>
      </li>)}</ol>}
    </section>
    {trajectory.confirmed_facts.length > 0 && <section aria-labelledby="facts-title"><h3 id="facts-title">已确认事实</h3><ul className="agent-facts">{trajectory.confirmed_facts.map((fact, index) => <li key={`${fact}-${index}`}>{fact}</li>)}</ul></section>}
    {trajectory.reason_codes.length > 0 && <section><h3>原因码</h3><div className="agent-reasons">{trajectory.reason_codes.map((code) => <code key={code}>{code}</code>)}</div></section>}
    <section aria-labelledby="roles-title"><h3 id="roles-title">角色状态</h3><div className="agent-role-grid">{trajectory.role_statuses.map((item) => <article key={item.role}><StatusBadge tone={item.status === 'completed' ? 'success' : 'info'}>{statusLabel(item.status)}</StatusBadge><h4>{roleLabel(item.role)}</h4><p>{item.summary ?? '尚未开始'}</p>{item.reason_code && <code>{item.reason_code}</code>}</article>)}</div></section>
    <section aria-labelledby="citations-title"><h3 id="citations-title">可信引用</h3>{trajectory.citations.length === 0 ? <p>暂无引用。</p> : <ul className="agent-citations">{trajectory.citations.map((item) => <li key={item.id}><strong>{item.kind}</strong><span>{item.source_id}</span><code>{item.integrity_sha256.slice(0, 12)}…</code></li>)}</ul>}</section>
  </div>
}

function ReactWorkspace({ trajectory, busy, reason, setReason, onControl }: { trajectory: ReactTrajectory; busy: boolean; reason: string; setReason: (value: string) => void; onControl: (action: 'takeover' | 'resume') => void }) {
  return <div className="agent-workspace react-workspace">
    <header><div><span className="agent-phase">Controlled ReAct</span><h3>循环轨迹</h3></div><StatusBadge tone={trajectory.status === 'human_takeover' ? 'warning' : 'info'}>{trajectory.status}</StatusBadge></header>
    <section aria-labelledby="react-budget-title"><h3 id="react-budget-title">循环预算</h3><div className="agent-metrics"><Metric label="迭代" used={trajectory.budget.loops_used} limit={trajectory.budget.loop_limit} /><Metric label="步骤" used={trajectory.budget.steps_used} limit={trajectory.budget.step_limit} /><Metric label="工具调用" used={trajectory.budget.tool_calls_used} limit={trajectory.budget.tool_call_limit} /></div></section>
    <section aria-labelledby="observations-title"><h3 id="observations-title">观察与分类</h3>{trajectory.observations.length === 0 ? <p>暂无公开观察。</p> : <ol className="react-timeline">{trajectory.observations.map((item) => { const assessment = trajectory.assessments.find((value) => value.observation_id === item.id); return <li key={item.id}><StatusBadge tone={item.status === 'succeeded' ? 'success' : 'warning'}>迭代 {item.iteration} · {item.status}</StatusBadge><strong>{item.source}</strong><code>{item.reason_code}</code>{item.tool_call_id && <small>可信调用：<code>{item.tool_call_id}</code></small>}{item.verification_id && <small>验证回执：<code>{item.verification_id}</code></small>}{assessment && <p>{assessment.category} · {assessment.recoverable ? '可恢复' : '不可恢复'} · {Math.round(assessment.confidence * 100)}%</p>}</li> })}</ol>}</section>
    <section aria-labelledby="plans-title"><h3 id="plans-title">计划差异</h3>{trajectory.plan_revisions.length === 0 ? <p>暂无重规划。</p> : <ol className="react-timeline">{trajectory.plan_revisions.map((item) => <li key={item.id}><strong>修订 {item.revision}</strong><p>{item.reason}</p><span>保留 {item.retained_action_ids.length} · 移除 {item.removed_action_ids.length} · 新增 {item.added_actions.length}</span>{item.added_actions.map((action) => <p key={action.id}>{action.action} → {action.target}</p>)}</li>)}</ol>}</section>
    <section aria-labelledby="decisions-title"><h3 id="decisions-title">决策</h3>{trajectory.decisions.length === 0 ? <p>暂无决策。</p> : <ol className="react-timeline">{trajectory.decisions.map((item) => <li key={item.id}><strong>{item.decision}</strong><code>{item.reason_code}</code></li>)}</ol>}</section>
    <section className="react-control" aria-labelledby="control-title"><h3 id="control-title">人工控制</h3><p>操作仍由服务端校验当前状态、操作者与修订边界。</p><label>操作原因<input value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} /></label><div><button disabled={busy || !reason.trim() || trajectory.status === 'human_takeover'} onClick={() => onControl('takeover')}>人工接管</button><button disabled={busy || !reason.trim() || trajectory.status !== 'human_takeover'} onClick={() => onControl('resume')}>恢复循环</button></div></section>
    {trajectory.controls.length > 0 && <section><h3>控制记录</h3><ol className="react-timeline">{trajectory.controls.map((item) => <li key={item.id}><strong>{item.action}</strong><span>{item.from_status} → {item.to_status}</span><code>{item.reason_code}</code></li>)}</ol></section>}
  </div>
}

export function AgentsPage({ initialRunId, embedded = false }: { initialRunId?: string; embedded?: boolean } = {}) {
  const { runId: contextRunId, setSelection } = useRunContext()
  const [runs, setRuns] = useState<AgentRunOption[]>([])
  const [runsLoading, setRunsLoading] = useState(true)
  const [runsError, setRunsError] = useState<string | null>(null)
  const [runId, setRunId] = useState(initialRunId ?? contextRunId ?? '')
  const [manualRunId, setManualRunId] = useState('')
  const [trajectory, setTrajectory] = useState<CollaborationTrajectory | null>(null)
  const [react, setReact] = useState<ReactTrajectory | null>(null)
  const [mcpCalls, setMcpCalls] = useState<McpRunCall[] | null>(null)
  const [collaborationIssue, setCollaborationIssue] = useState<LoadIssue | null>(null)
  const [reactIssue, setReactIssue] = useState<LoadIssue | null>(null)
  const [mcpIssue, setMcpIssue] = useState<LoadIssue | null>(null)
  const [controlMessage, setControlMessage] = useState<string | null>(null)
  const [reason, setReason] = useState('人工复核运行轨迹')
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | null>(null)
  const historyActive = useRef<AbortController | null>(null)

  const loadRun = useCallback(async (selected: string) => {
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    setRunId(selected); setBusy(true); setCollaborationIssue(null); setReactIssue(null); setMcpIssue(null); setControlMessage(null)
    const [collaborationResult, reactResult, mcpResult] = await Promise.allSettled([getCollaborationTrajectory(selected, controller.signal), getReactTrajectory(selected, controller.signal), getMcpRunCalls(selected, controller.signal)])
    if (!controller.signal.aborted) {
      if (collaborationResult.status === 'fulfilled') setTrajectory(collaborationResult.value)
      else { setTrajectory(null); setCollaborationIssue(loadIssue(collaborationResult.reason, 'collaboration')) }
      if (reactResult.status === 'fulfilled') setReact(reactResult.value)
      else { setReact(null); setReactIssue(loadIssue(reactResult.reason, 'react')) }
      if (mcpResult.status === 'fulfilled') setMcpCalls(mcpResult.value)
      else { setMcpCalls(null); setMcpIssue(loadIssue(mcpResult.reason, 'mcp')) }
    }
    if (active.current === controller) active.current = null
    if (!controller.signal.aborted) setBusy(false)
  }, [])

  const chooseRun = useCallback((selected: string, availableRuns: AgentRunOption[]) => {
    if (!selected) return
    const option = availableRuns.find((item) => item.run_id === selected)
    if (!embedded && contextRunId !== selected) setSelection({ runId: selected, incidentId: option?.incident_id ?? null })
    void loadRun(selected)
  }, [contextRunId, embedded, loadRun, setSelection])

  const refreshRuns = useCallback(() => {
    historyActive.current?.abort()
    const controller = new AbortController()
    historyActive.current = controller
    setRunsLoading(true); setRunsError(null)
    void listAgentRuns(controller.signal).then((items) => {
      if (controller.signal.aborted) return
      setRuns(items)
      const preferred = initialRunId ?? contextRunId ?? items[0]?.run_id ?? ''
      if (preferred) chooseRun(preferred, items)
    }).catch((failure) => {
      if (!controller.signal.aborted) setRunsError(failure instanceof Error ? failure.message : '运行列表加载失败，请稍后重试。')
    }).finally(() => {
      if (historyActive.current === controller) historyActive.current = null
      if (!controller.signal.aborted) setRunsLoading(false)
    })
  }, [chooseRun, contextRunId, initialRunId])

  useEffect(() => {
    if (!embedded || !initialRunId) return
    void loadRun(initialRunId)
    return () => active.current?.abort()
  }, [embedded, initialRunId, loadRun])

  useEffect(() => {
    if (embedded && initialRunId) return
    refreshRuns()
    return () => { historyActive.current?.abort(); active.current?.abort() }
  }, [embedded, initialRunId, refreshRuns])

  const loadManual = (event: FormEvent) => { event.preventDefault(); const selected = manualRunId.trim(); if (selected) chooseRun(selected, runs) }
  const control = async (action: 'takeover' | 'resume') => {
    if (!react || !reason.trim()) return
    active.current?.abort(); const controller = new AbortController(); active.current = controller; setBusy(true); setControlMessage(null)
    try { const result = await controlReactLoop(react.loop_id, action, reason.trim(), controller.signal); if (!controller.signal.aborted) { await loadRun(runId); setControlMessage(`${action === 'takeover' ? '人工接管' : '恢复循环'}成功：${result.status}`) } }
    catch (failure) { if (!controller.signal.aborted) setControlMessage(failure instanceof Error ? failure.message : 'ReAct 控制失败') }
    finally { if (active.current === controller) active.current = null; if (!controller.signal.aborted) setBusy(false) }
  }

  const selectedRun = runs.find((item) => item.run_id === runId)
  const missingIssues = [collaborationIssue, reactIssue, mcpIssue].filter((item): item is LoadIssue => item?.kind === 'missing')
  const errorIssues = [collaborationIssue, reactIssue, mcpIssue].filter((item): item is LoadIssue => item?.kind === 'error')

  return <section aria-label={embedded ? '智能体与 ReAct 公开轨迹' : undefined} aria-labelledby={embedded ? undefined : 'agents-title'} className={`page-card agents-page${embedded ? ' agents-page--embedded' : ''}`}>
    {!embedded && <PageHeader id="agents-title" eyebrow="共享智能" title="智能体与 ReAct 工作台" description="选择最近调查即可查看真实角色交接、工具调用与受控循环；不展示私有上下文、原始提示、隐藏思维链或凭据。" actions={<button disabled={runsLoading} type="button" onClick={refreshRuns}>{runsLoading ? '刷新中…' : '刷新运行'}</button>} />}
    {!embedded && <section className="agent-run-picker" aria-labelledby="recent-runs-title">
      <div className="agent-section-heading"><div><h3 id="recent-runs-title">选择调查运行</h3><p>默认打开最近一条记录，无需复制运行 ID。</p></div>{runs.length > 0 && <span>{runs.length} 条</span>}</div>
      {runsLoading && runs.length === 0 ? <LoadingState title="正在加载最近运行" detail="正在读取可追溯的调查记录。" /> : runs.length > 0 ? <><label htmlFor="agent-run-select">最近调查运行</label><select id="agent-run-select" value={runId} disabled={busy} onChange={(event) => chooseRun(event.target.value, runs)}>{runs.map((item) => <option key={item.run_id} value={item.run_id}>{item.incident_tracking_id} · {item.threat_label} · {statusLabel(item.status)} · {dateTime(item.updated_at)}</option>)}</select></> : !runsError && <EmptyState title="暂无调查运行" detail="先在调查页面启动一次运行，记录会自动出现在这里。" />}
      {runsError && <p role="alert" className="agent-error">{runsError}</p>}
      {selectedRun && <dl className="agent-run-summary"><div><dt>事件</dt><dd>{selectedRun.incident_tracking_id}</dd></div><div><dt>目标</dt><dd>{selectedRun.endpoint}</dd></div><div><dt>状态</dt><dd>{statusLabel(selectedRun.status)}</dd></div><div><dt>最近更新</dt><dd>{dateTime(selectedRun.updated_at)}</dd></div></dl>}
      <details className="agent-manual-run"><summary>高级：使用运行 ID</summary><form className="agent-run-form" onSubmit={loadManual}><label htmlFor="agent-run-id">调查运行 ID</label><div><input id="agent-run-id" value={manualRunId} onChange={(event) => setManualRunId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /><button disabled={busy || !manualRunId.trim()} type="submit">查看轨迹</button></div></form></details>
    </section>}
    {busy && <p className="agent-loading" role="status">正在加载该运行的公开轨迹…</p>}
    {missingIssues.length > 0 && <aside className="agent-availability" aria-label="轨迹数据说明"><strong>本次运行的数据范围</strong><ul>{missingIssues.map((item) => <li key={item.message}>{item.message}</li>)}</ul></aside>}
    {errorIssues.map((item) => <p role="alert" className="agent-error" key={item.message}>{item.message}</p>)}
    {controlMessage && <p role="status" className="agent-control-message">{controlMessage}</p>}
    {trajectory && <Collaboration trajectory={trajectory} />}
    {mcpCalls && <section className="agent-workspace agent-tool-workspace" aria-labelledby="agent-tools-title"><header><div><span className="agent-phase">Agent Tool / MCP</span><h3 id="agent-tools-title">工具选择与公开回执</h3></div><strong>{mcpCalls.length} 次调用</strong></header>{mcpCalls.length === 0 ? <p>本次运行未选择只读工具。</p> : <ol className="react-timeline">{mcpCalls.map((call) => <li key={call.id}><div><StatusBadge tone={call.status === 'succeeded' || call.status === 'empty' ? 'success' : 'warning'}>{call.status}</StatusBadge> <strong>{call.tool_alias}</strong></div><span>{call.provider_kind === 'remote_mcp' ? '外部 MCP' : call.provider_kind === 'rag' ? '本地 RAG' : '内置工具'} · 目录 {call.catalog_revision} · Schema {call.schema_revision}</span><p>{call.summary ?? '尚无公开回执摘要。'}</p>{call.reason_code && <code>{call.reason_code}</code>}</li>)}</ol>}</section>}
    {react && <ReactWorkspace trajectory={react} busy={busy} reason={reason} setReason={setReason} onControl={(action) => void control(action)} />}
  </section>
}
