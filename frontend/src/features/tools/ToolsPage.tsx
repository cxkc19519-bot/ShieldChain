import { type FormEvent, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, LoadingState } from '../../components/ui/States'
import { controlToolCall, decideToolCall, getToolTrace, setEmergencyStop } from './api'
import './tools.css'
import type { ToolTrace } from './types'

type CallAction = 'approved' | 'rejected' | 'pause' | 'resume' | 'cancel'
type Message = { kind: 'error' | 'success'; text: string }

const labels: Record<CallAction, string> = {
  approved: '批准', rejected: '拒绝', pause: '暂停', resume: '恢复', cancel: '取消',
}
const preDispatch = new Set(['proposed', 'policy_checked', 'awaiting_approval', 'approved'])

function actionsFor(status: string): CallAction[] {
  const actions: CallAction[] = []
  if (status === 'awaiting_approval') actions.push('approved', 'rejected')
  if (preDispatch.has(status)) actions.push('pause', 'cancel')
  if (status === 'paused') actions.push('resume', 'cancel')
  return actions
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : '操作失败'
}

export function ToolsPage() {
  const context = useRunContext()
  const [runId, setRunId] = useState(context.runId ?? '')
  const [trace, setTrace] = useState<ToolTrace | null>(null)
  const [reason, setReason] = useState('人工复核后执行')
  const [message, setMessage] = useState<Message | null>(null)
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])
  useEffect(() => {
    active.current?.abort()
    setRunId(context.runId ?? '')
    setTrace(null)
    setMessage(null)
    setBusy(false)
  }, [context.runId])

  const load = async (event?: FormEvent) => {
    event?.preventDefault()
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    setBusy(true); setMessage(null)
    setTrace(null)
    try { setTrace(await getToolTrace(runId.trim(), controller.signal)) }
    catch (error) { if (!controller.signal.aborted) setMessage({ kind: 'error', text: errorMessage(error) }) }
    finally { if (active.current === controller) active.current = null; setBusy(false) }
  }

  const refreshAfterMutation = async (outcome: Message): Promise<Message> => {
    if (!runId.trim()) return outcome
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    try {
      setTrace(await getToolTrace(runId.trim(), controller.signal))
      return outcome
    } catch (error) {
      if (controller.signal.aborted) return outcome
      return { kind: 'error', text: `${outcome.text}；可信状态刷新失败：${errorMessage(error)}` }
    } finally {
      if (active.current === controller) active.current = null
    }
  }

  const act = async (callId: string, action: CallAction) => {
    if (!reason.trim()) { setMessage({ kind: 'error', text: '请填写操作原因' }); return }
    setBusy(true); setMessage(null)
    let outcome: Message
    try {
      const result = action === 'approved' || action === 'rejected'
        ? await decideToolCall(callId, action, reason.trim())
        : await controlToolCall(callId, action, reason.trim())
      outcome = { kind: 'success', text: `${labels[action]}已提交：${result.status}` }
    } catch (error) { outcome = { kind: 'error', text: errorMessage(error) } }
    setMessage(await refreshAfterMutation(outcome))
    setBusy(false)
  }

  const emergency = async (activeStop: boolean) => {
    if (!reason.trim()) { setMessage({ kind: 'error', text: '请填写操作原因' }); return }
    if (activeStop && !window.confirm('确认紧急停止所有尚未下发的自动化处置？已下发动作不会被宣称为撤回。')) return
    setBusy(true); setMessage(null)
    let outcome: Message
    try {
      const result = await setEmergencyStop(activeStop, reason.trim())
      outcome = { kind: 'success', text: activeStop ? `紧急停止已启用：${result.status}` : `自动化已恢复：${result.status}` }
    } catch (error) { outcome = { kind: 'error', text: errorMessage(error) } }
    setMessage(await refreshAfterMutation(outcome))
    setBusy(false)
  }

  return (
    <section aria-labelledby="tools-title" className="page-card tools-page">
      <PageHeader id="tools-title" eyebrow="可信执行边界" title="处置中心" description="按服务端策略、风险和状态审核处置调用；执行与验证结果只以公开可信投影为准。" />
      <p className="tools-privacy">仅展示策略、审批、执行尝试、验证结果与证据引用；不展示原始结果、凭据或私有推理。</p>

      <div className="tools-control-panel">
        <form className="tools-form" onSubmit={(event) => void load(event)}>
          <label htmlFor="tool-run-id">调查运行 ID</label>
          <div>
            <input id="tool-run-id" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            <button disabled={busy || !runId.trim()}>查看处置轨迹</button>
          </div>
        </form>
        <label className="tools-reason" htmlFor="tool-action-reason">操作原因</label>
        <input id="tool-action-reason" className="tools-reason-input" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={512} />
        <div className="tools-emergency" aria-label="全局自动化控制">
          <button className="danger-button" disabled={busy} type="button" onClick={() => void emergency(true)}>紧急停止自动化</button>
          <button disabled={busy} type="button" onClick={() => void emergency(false)}>恢复自动化</button>
        </div>
        <p className="tools-control-note">紧急停止只阻止尚未下发的调用；执行中与验证中的动作必须继续查询和核验。</p>
      </div>

      {message && <p aria-live="polite" role={message.kind === 'error' ? 'alert' : 'status'} className={`tools-message tools-message--${message.kind}`}>{message.text}</p>}
      {busy && !trace && <LoadingState title="正在读取处置轨迹" detail="正在从服务端刷新策略、执行与验证状态。" />}
      {!busy && !trace && !message && <EmptyState title="尚未加载处置轨迹" detail="输入调查运行 ID，查看该运行的可信工具调用。" />}
      {trace && trace.calls.length === 0 && <EmptyState title="没有公开处置调用" detail="该调查运行当前没有可展示的可信工具调用。" />}
      {trace && trace.calls.length > 0 && (
        <section aria-labelledby="tool-calls-title">
          <div className="tools-trace-heading"><div><p className="eyebrow">运行 {trace.run_id}</p><h3 id="tool-calls-title">可信处置轨迹</h3></div><strong>{trace.calls.length} 个调用</strong></div>
          <div className="tools-grid">{trace.calls.map((call) => {
            const actions = actionsFor(call.status)
            return <article key={call.id} className={`tool-call tool-call--${call.risk ?? 'unknown'}`}>
              <header>
                <div className="tool-call__identity"><div><span className="status-badge">{call.status}</span><span className="risk-badge">风险 {call.risk ?? '待评估'}</span></div><h3>{call.tool_name} <small>v{call.tool_version}</small></h3></div>
                <code>{call.target}</code>
              </header>
              <dl>
                <div><dt>服务端风险</dt><dd>{call.risk ?? '待评估'}</dd></div>
                <div><dt>策略</dt><dd>{call.policy_outcome ?? '待定'}</dd></div>
                <div><dt>审批</dt><dd>{call.approval_outcome ?? '待定'}</dd></div>
                <div><dt>验证</dt><dd>{call.verification_outcome ?? '待验证'}</dd></div>
                <div><dt>原因码</dt><dd>{call.reason ?? '无'}</dd></div>
              </dl>
              <section className="tool-call__details" aria-label={`${call.tool_name} 执行与证据`}>
                <div><h4>执行尝试</h4>{call.attempt_outcomes.length ? <ol>{call.attempt_outcomes.map((outcome, index) => <li key={`${index}-${outcome}`}>第 {index + 1} 次 · {outcome}</li>)}</ol> : <p>尚未执行</p>}</div>
                <div><h4>证据引用</h4>{call.evidence_ids.length ? <ul>{call.evidence_ids.map((id) => <li key={id}><code>{id}</code></li>)}</ul> : <p>无公开证据引用</p>}</div>
              </section>
              <p className="tool-call__time">最后更新：<time dateTime={call.updated_at}>{call.updated_at}</time></p>
              <footer>
                {actions.map((action) => <button className={action === 'rejected' || action === 'cancel' ? 'secondary-button' : ''} disabled={busy} key={action} type="button" onClick={() => void act(call.id, action)}>{labels[action]}</button>)}
                {actions.length === 0 && <span>当前状态无可用人工动作</span>}
              </footer>
            </article>
          })}</div>
        </section>
      )}
    </section>
  )
}
