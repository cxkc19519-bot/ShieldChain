import { type FormEvent, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { controlToolCall, decideToolCall, getToolTrace, setEmergencyStop } from './api'
import './tools.css'
import type { ToolTrace } from './types'

const labels: Record<string, string> = {
  approved: '批准', rejected: '拒绝', pause: '暂停', resume: '恢复', cancel: '取消',
}

export function ToolsPage() {
  const context = useRunContext()
  const [runId, setRunId] = useState(context.runId ?? '')
  const [trace, setTrace] = useState<ToolTrace | null>(null)
  const [reason, setReason] = useState('人工复核后执行')
  const [message, setMessage] = useState<string | null>(null)
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
    try { setTrace(await getToolTrace(runId.trim(), controller.signal)) }
    catch (error) { if (!controller.signal.aborted) setMessage(error instanceof Error ? error.message : '无法加载处置轨迹') }
    finally { if (active.current === controller) active.current = null; setBusy(false) }
  }

  const act = async (callId: string, action: 'approved' | 'rejected' | 'pause' | 'resume' | 'cancel') => {
    if (!reason.trim()) { setMessage('请填写操作原因'); return }
    setBusy(true); setMessage(null)
    try {
      const result = action === 'approved' || action === 'rejected'
        ? await decideToolCall(callId, action, reason.trim())
        : await controlToolCall(callId, action, reason.trim())
      setMessage(`${labels[action]}成功：${result.status}`)
      await load()
    } catch (error) { setMessage(error instanceof Error ? error.message : '操作失败') }
    finally { setBusy(false) }
  }

  const emergency = async (activeStop: boolean) => {
    if (!reason.trim()) { setMessage('请填写操作原因'); return }
    setBusy(true); setMessage(null)
    try {
      const result = await setEmergencyStop(activeStop, reason.trim())
      setMessage(activeStop ? `紧急停止已启用：${result.status}` : `自动化已恢复：${result.status}`)
    } catch (error) { setMessage(error instanceof Error ? error.message : '操作失败') }
    finally { setBusy(false) }
  }

  return <section aria-labelledby="tools-title" className="page-card tools-page">
    <p className="eyebrow">可信执行边界</p>
    <h2 id="tools-title">处置中心</h2>
    <p className="tools-privacy">仅展示策略、审批、执行尝试、验证结果与证据引用；不展示原始结果、凭据或私有推理。</p>
    <form className="tools-form" onSubmit={(event) => void load(event)}>
      <label htmlFor="tool-run-id">调查运行 ID</label>
      <div><input id="tool-run-id" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/><button disabled={busy || !runId.trim()}>查看处置轨迹</button></div>
    </form>
    <label className="tools-reason">操作原因<input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={512}/></label>
    <div className="tools-emergency"><button disabled={busy} onClick={() => void emergency(true)}>紧急停止自动化</button><button disabled={busy} onClick={() => void emergency(false)}>恢复自动化</button></div>
    {message && <p role="status" className="tools-message">{message}</p>}
    {trace && <div className="tools-grid">{trace.calls.map((call) => <article key={call.id}>
      <header><div><span>{call.status}</span><h3>{call.tool_name} <small>v{call.tool_version}</small></h3></div><code>{call.target}</code></header>
      <dl><div><dt>策略</dt><dd>{call.policy_outcome ?? '待定'}</dd></div><div><dt>审批</dt><dd>{call.approval_outcome ?? '待定'}</dd></div><div><dt>验证</dt><dd>{call.verification_outcome ?? '待验证'}</dd></div><div><dt>原因码</dt><dd>{call.reason ?? '无'}</dd></div></dl>
      <p><strong>执行尝试：</strong>{call.attempt_outcomes.length ? call.attempt_outcomes.join('、') : '尚未执行'}</p>
      <p><strong>证据引用：</strong>{call.evidence_ids.length ? call.evidence_ids.join('、') : '无'}</p>
      <footer>{(['approved', 'rejected', 'pause', 'resume', 'cancel'] as const).map((action) => <button disabled={busy} key={action} onClick={() => void act(call.id, action)}>{labels[action]}</button>)}</footer>
    </article>)}</div>}
  </section>
}
