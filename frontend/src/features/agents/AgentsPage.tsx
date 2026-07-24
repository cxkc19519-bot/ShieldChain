import { type FormEvent, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { getCollaborationTrajectory } from './api'
import './agents.css'
import type { CollaborationTrajectory } from './types'

function Metric({ label, used, limit }: { label: string; used: number; limit: number }) {
  return <div className="agent-metric"><span>{label}</span><strong>{used} / {limit}</strong></div>
}

export function AgentsPage() {
  const context = useRunContext()
  const [runId, setRunId] = useState(context.runId ?? '')
  const [trajectory, setTrajectory] = useState<CollaborationTrajectory | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | null>(null)

  useEffect(() => () => active.current?.abort(), [])
  useEffect(() => {
    active.current?.abort()
    setRunId(context.runId ?? '')
    setTrajectory(null)
    setError(null)
    setBusy(false)
  }, [context.runId])

  const load = async (event: FormEvent) => {
    event.preventDefault()
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    setBusy(true)
    setError(null)
    try {
      setTrajectory(await getCollaborationTrajectory(runId.trim(), controller.signal))
    } catch (reason) {
      if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : '无法加载轨迹')
    } finally {
      if (active.current === controller) active.current = null
      setBusy(false)
    }
  }

  return (
    <section aria-labelledby="agents-title" className="page-card agents-page">
      <p className="eyebrow">只读协作视图</p>
      <h2 id="agents-title">智能体工作台</h2>
      <p className="agent-privacy">仅展示共享案件摘要、状态与可信引用；不展示私有上下文、原始提示或思维链。</p>
      <form className="agent-run-form" onSubmit={(event) => void load(event)}>
        <label htmlFor="agent-run-id">调查运行 ID</label>
        <div><input id="agent-run-id" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
          <button disabled={busy || !runId.trim()} type="submit">{busy ? '加载中…' : '查看协作轨迹'}</button></div>
      </form>
      {error && <p role="alert" className="agent-error">{error}</p>}
      {trajectory && <div className="agent-workspace">
        <header><div><span className="agent-phase">{trajectory.phase}</span><h3>{trajectory.shared_summary}</h3></div><small>修订 {trajectory.revision}</small></header>
        <section aria-labelledby="budget-title"><h3 id="budget-title">预算</h3><div className="agent-metrics">
          <Metric label="步骤" used={trajectory.budget.steps_used} limit={trajectory.budget.step_limit} />
          <Metric label="Token" used={trajectory.budget.tokens_used} limit={trajectory.budget.token_limit} />
          <Metric label="工具调用" used={trajectory.budget.tool_calls_used} limit={trajectory.budget.tool_call_limit} />
        </div></section>
        {trajectory.reason_codes.length > 0 && <section><h3>原因码</h3><div className="agent-reasons">{trajectory.reason_codes.map((code) => <code key={code}>{code}</code>)}</div></section>}
        <section aria-labelledby="roles-title"><h3 id="roles-title">角色状态</h3><div className="agent-role-grid">{trajectory.role_statuses.map((item) => <article key={item.role}><span>{item.status}</span><h4>{item.role}</h4><p>{item.summary ?? '尚未开始'}</p>{item.reason_code && <code>{item.reason_code}</code>}</article>)}</div></section>
        <section aria-labelledby="handoffs-title"><h3 id="handoffs-title">结构化交接</h3>{trajectory.handoffs.length === 0 ? <p>暂无交接。</p> : <ol className="agent-handoffs">{trajectory.handoffs.map((item) => <li key={item.id}><strong>{item.sender} → {item.receiver}</strong><p>{item.conclusion}</p><small>置信度 {Math.round(item.confidence * 100)}%</small></li>)}</ol>}</section>
        <section aria-labelledby="citations-title"><h3 id="citations-title">可信引用</h3>{trajectory.citations.length === 0 ? <p>暂无引用。</p> : <ul className="agent-citations">{trajectory.citations.map((item) => <li key={item.id}><strong>{item.kind}</strong><span>{item.source_id}</span><code>{item.integrity_sha256.slice(0, 12)}…</code></li>)}</ul>}</section>
      </div>}
    </section>
  )
}
