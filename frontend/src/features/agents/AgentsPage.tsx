import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { EmptyState } from '../../components/ui/States'
import { PageHeader } from '../../components/ui/PageHeader'
import { StatusBadge } from '../../components/ui/StatusBadge'
import { getCollaborationTrajectory } from './api'
import { controlReactLoop, getReactTrajectory } from './reactApi'
import type { ReactTrajectory } from './reactTypes'
import type { CollaborationTrajectory } from './types'
import './agents.css'

function Metric({ label, used, limit }: { label: string; used: number; limit: number }) {
  return <div className="agent-metric"><span>{label}</span><strong>{used} / {limit}</strong></div>
}

function Collaboration({ trajectory }: { trajectory: CollaborationTrajectory }) {
  return <div className="agent-workspace collaboration-workspace">
    <header><div><span className="agent-phase">{trajectory.phase}</span><h3>{trajectory.shared_summary}</h3></div><small>修订 {trajectory.revision}</small></header>
    <section aria-labelledby="budget-title"><h3 id="budget-title">协作预算</h3><div className="agent-metrics"><Metric label="步骤" used={trajectory.budget.steps_used} limit={trajectory.budget.step_limit} /><Metric label="Token" used={trajectory.budget.tokens_used} limit={trajectory.budget.token_limit} /><Metric label="工具调用" used={trajectory.budget.tool_calls_used} limit={trajectory.budget.tool_call_limit} /></div></section>
    {trajectory.reason_codes.length > 0 && <section><h3>原因码</h3><div className="agent-reasons">{trajectory.reason_codes.map((code) => <code key={code}>{code}</code>)}</div></section>}
    <section aria-labelledby="roles-title"><h3 id="roles-title">角色状态</h3><div className="agent-role-grid">{trajectory.role_statuses.map((item) => <article key={item.role}><StatusBadge tone={item.status === 'completed' ? 'success' : 'info'}>{item.status}</StatusBadge><h4>{item.role}</h4><p>{item.summary ?? '尚未开始'}</p>{item.reason_code && <code>{item.reason_code}</code>}</article>)}</div></section>
    <section aria-labelledby="handoffs-title"><h3 id="handoffs-title">结构化交接</h3>{trajectory.handoffs.length === 0 ? <p>暂无交接。</p> : <ol className="agent-handoffs">{trajectory.handoffs.map((item) => <li key={item.id}><strong>{item.sender} → {item.receiver}</strong><p>{item.conclusion}</p><small>置信度 {Math.round(item.confidence * 100)}%</small></li>)}</ol>}</section>
    <section aria-labelledby="citations-title"><h3 id="citations-title">可信引用</h3>{trajectory.citations.length === 0 ? <p>暂无引用。</p> : <ul className="agent-citations">{trajectory.citations.map((item) => <li key={item.id}><strong>{item.kind}</strong><span>{item.source_id}</span><code>{item.integrity_sha256.slice(0, 12)}…</code></li>)}</ul>}</section>
  </div>
}

function ReactWorkspace({ trajectory, busy, reason, setReason, onControl }: { trajectory: ReactTrajectory; busy: boolean; reason: string; setReason: (value: string) => void; onControl: (action: 'takeover' | 'resume') => void }) {
  return <div className="agent-workspace react-workspace">
    <header><div><span className="agent-phase">Controlled ReAct</span><h3>循环轨迹</h3></div><StatusBadge tone={trajectory.status === 'human_takeover' ? 'warning' : 'info'}>{trajectory.status}</StatusBadge></header>
    <section aria-labelledby="react-budget-title"><h3 id="react-budget-title">循环预算</h3><div className="agent-metrics"><Metric label="迭代" used={trajectory.budget.loops_used} limit={trajectory.budget.loop_limit} /><Metric label="步骤" used={trajectory.budget.steps_used} limit={trajectory.budget.step_limit} /><Metric label="工具调用" used={trajectory.budget.tool_calls_used} limit={trajectory.budget.tool_call_limit} /></div></section>
    <section aria-labelledby="observations-title"><h3 id="observations-title">观察与分类</h3>{trajectory.observations.length === 0 ? <p>暂无公开观察。</p> : <ol className="react-timeline">{trajectory.observations.map((item) => { const assessment = trajectory.assessments.find((value) => value.observation_id === item.id); return <li key={item.id}><StatusBadge tone={item.status === 'succeeded' ? 'success' : 'warning'}>迭代 {item.iteration} · {item.status}</StatusBadge><strong>{item.source}</strong><code>{item.reason_code}</code>{assessment && <p>{assessment.category} · {assessment.recoverable ? '可恢复' : '不可恢复'} · {Math.round(assessment.confidence * 100)}%</p>}</li> })}</ol>}</section>
    <section aria-labelledby="plans-title"><h3 id="plans-title">计划差异</h3>{trajectory.plan_revisions.length === 0 ? <p>暂无重规划。</p> : <ol className="react-timeline">{trajectory.plan_revisions.map((item) => <li key={item.id}><strong>修订 {item.revision}</strong><p>{item.reason}</p><span>保留 {item.retained_action_ids.length} · 移除 {item.removed_action_ids.length} · 新增 {item.added_actions.length}</span>{item.added_actions.map((action) => <p key={action.id}>{action.action} → {action.target}</p>)}</li>)}</ol>}</section>
    <section aria-labelledby="decisions-title"><h3 id="decisions-title">决策</h3>{trajectory.decisions.length === 0 ? <p>暂无决策。</p> : <ol className="react-timeline">{trajectory.decisions.map((item) => <li key={item.id}><strong>{item.decision}</strong><code>{item.reason_code}</code></li>)}</ol>}</section>
    <section className="react-control" aria-labelledby="control-title"><h3 id="control-title">人工控制</h3><p>操作仍由服务端校验当前状态、操作者与修订边界。</p><label>操作原因<input value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} /></label><div><button disabled={busy || !reason.trim() || trajectory.status === 'human_takeover'} onClick={() => onControl('takeover')}>人工接管</button><button disabled={busy || !reason.trim() || trajectory.status !== 'human_takeover'} onClick={() => onControl('resume')}>恢复循环</button></div></section>
    {trajectory.controls.length > 0 && <section><h3>控制记录</h3><ol className="react-timeline">{trajectory.controls.map((item) => <li key={item.id}><strong>{item.action}</strong><span>{item.from_status} → {item.to_status}</span><code>{item.reason_code}</code></li>)}</ol></section>}
  </div>
}

export function AgentsPage() {
  const context = useRunContext()
  const [runId, setRunId] = useState(context.runId ?? '')
  const [trajectory, setTrajectory] = useState<CollaborationTrajectory | null>(null)
  const [react, setReact] = useState<ReactTrajectory | null>(null)
  const [collaborationError, setCollaborationError] = useState<string | null>(null)
  const [reactError, setReactError] = useState<string | null>(null)
  const [controlMessage, setControlMessage] = useState<string | null>(null)
  const [reason, setReason] = useState('人工复核运行轨迹')
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | null>(null)

  const loadRun = useCallback(async (selected: string) => {
    active.current?.abort()
    const controller = new AbortController(); active.current = controller
    setBusy(true); setCollaborationError(null); setReactError(null); setControlMessage(null)
    const [collaborationResult, reactResult] = await Promise.allSettled([getCollaborationTrajectory(selected, controller.signal), getReactTrajectory(selected, controller.signal)])
    if (!controller.signal.aborted) {
      if (collaborationResult.status === 'fulfilled') setTrajectory(collaborationResult.value)
      else { setTrajectory(null); setCollaborationError(collaborationResult.reason instanceof Error ? collaborationResult.reason.message : '无法加载协作轨迹') }
      if (reactResult.status === 'fulfilled') setReact(reactResult.value)
      else { setReact(null); setReactError(reactResult.reason instanceof Error ? reactResult.reason.message : '无法加载 ReAct 轨迹') }
    }
    if (active.current === controller) active.current = null
    if (!controller.signal.aborted) setBusy(false)
  }, [])

  useEffect(() => () => active.current?.abort(), [])
  useEffect(() => { active.current?.abort(); setRunId(context.runId ?? ''); setTrajectory(null); setReact(null); setCollaborationError(null); setReactError(null); setBusy(false) }, [context.runId])

  const load = (event: FormEvent) => { event.preventDefault(); void loadRun(runId.trim()) }
  const control = async (action: 'takeover' | 'resume') => {
    if (!react || !reason.trim()) return
    active.current?.abort(); const controller = new AbortController(); active.current = controller; setBusy(true); setControlMessage(null)
    try { const result = await controlReactLoop(react.loop_id, action, reason.trim(), controller.signal); if (!controller.signal.aborted) { await loadRun(runId.trim()); setControlMessage(`${action === 'takeover' ? '人工接管' : '恢复循环'}成功：${result.status}`) } }
    catch (failure) { if (!controller.signal.aborted) setControlMessage(failure instanceof Error ? failure.message : 'ReAct 控制失败') }
    finally { if (active.current === controller) active.current = null; if (!controller.signal.aborted) setBusy(false) }
  }

  return <section aria-labelledby="agents-title" className="page-card agents-page">
    <PageHeader eyebrow="Shared intelligence" title="智能体与 ReAct 工作台" description="组合公开协作与受控循环轨迹；不展示私有上下文、原始提示、思维链或凭据。" />
    <form className="agent-run-form" onSubmit={load}><label htmlFor="agent-run-id">调查运行 ID</label><div><input id="agent-run-id" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /><button disabled={busy || !runId.trim()} type="submit">{busy ? '加载中…' : '查看联合轨迹'}</button></div></form>
    {!runId.trim() && <EmptyState title="尚未选择运行" detail="从调查页启动运行，或输入已有运行 ID。" />}
    {collaborationError && <p role="alert" className="agent-error">协作轨迹：{collaborationError}</p>}
    {reactError && <p role="alert" className="agent-error">ReAct 轨迹：{reactError}</p>}
    {controlMessage && <p role="status" className="agent-control-message">{controlMessage}</p>}
    {trajectory && <Collaboration trajectory={trajectory} />}
    {react && <ReactWorkspace trajectory={react} busy={busy} reason={reason} setReason={setReason} onControl={(action) => void control(action)} />}
  </section>
}
