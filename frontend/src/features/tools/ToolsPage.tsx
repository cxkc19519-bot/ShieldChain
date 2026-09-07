import { type FormEvent, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, LoadingState } from '../../components/ui/States'
import { getMcpRunCalls } from '../mcp/api'
import type { McpRunCall } from '../mcp/types'
import { controlToolCall, decideResponsePlan, decideToolCall, getResponsePlan, getToolTrace, setEmergencyStop } from './api'
import './tools.css'
import type { ResponsePlan, ToolTrace } from './types'

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

export function ToolsPage({ initialRunId, embedded = false }: { initialRunId?: string; embedded?: boolean } = {}) {
  const context = useRunContext()
  const [runId, setRunId] = useState(initialRunId ?? context.runId ?? '')
  const [trace, setTrace] = useState<ToolTrace | null>(null)
  const [plan, setPlan] = useState<ResponsePlan | null>(null)
  const [mcpCalls, setMcpCalls] = useState<McpRunCall[] | null>(null)
  const [partialErrors, setPartialErrors] = useState<string[]>([])
  const [reason, setReason] = useState('人工复核后执行')
  const [message, setMessage] = useState<Message | null>(null)
  const [busy, setBusy] = useState(false)
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])
  useEffect(() => {
    if (initialRunId) return
    active.current?.abort()
    setRunId(context.runId ?? '')
    setTrace(null)
    setPlan(null)
    setMcpCalls(null)
    setPartialErrors([])
    setMessage(null)
    setBusy(false)
  }, [context.runId, initialRunId])

  const loadData = async (selectedRunId: string, controller: AbortController) => {
    const [planResult, traceResult, mcpResult] = await Promise.allSettled([
      getResponsePlan(selectedRunId, controller.signal),
      getToolTrace(selectedRunId, controller.signal),
      getMcpRunCalls(selectedRunId, controller.signal),
    ])
    if (controller.signal.aborted) return []
    const errors: string[] = []
    if (planResult.status === 'fulfilled') setPlan(planResult.value)
    else { setPlan(null); errors.push(`响应计划：${errorMessage(planResult.reason)}`) }
    if (traceResult.status === 'fulfilled') setTrace(traceResult.value)
    else { setTrace(null); errors.push(`可信处置：${errorMessage(traceResult.reason)}`) }
    if (mcpResult.status === 'fulfilled') setMcpCalls(mcpResult.value)
    else { setMcpCalls(null); errors.push(`MCP 调用：${errorMessage(mcpResult.reason)}`) }
    setPartialErrors(errors)
    return errors
  }

  const load = async (event?: FormEvent) => {
    event?.preventDefault()
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    setBusy(true); setMessage(null)
    setTrace(null); setPlan(null); setMcpCalls(null); setPartialErrors([])
    try {
      const errors = await loadData(runId.trim(), controller)
      if (!controller.signal.aborted && errors.length === 3) setMessage({ kind: 'error', text: errors.join('；') })
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false) }
    }
  }

  useEffect(() => {
    if (embedded && initialRunId) void load()
    // The report workspace remounts this component for each selected run.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [embedded, initialRunId])
  const refreshAfterMutation = async (outcome: Message): Promise<Message> => {
    // Global automation control is valid even when a historical run has no
    // trusted-tool calls. Keep a successful switch from being overwritten by a trace 404.
    if (!runId.trim()) return outcome
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    try {
      const errors = await loadData(runId.trim(), controller)
      return errors.length === 3
        ? { kind: 'error', text: `${outcome.text}；公开状态刷新失败` }
        : outcome
    } catch (error) {
      if (controller.signal.aborted) return outcome
      return { kind: 'error', text: `${outcome.text}；可信状态刷新失败：${errorMessage(error)}` }
    } finally {
      if (active.current === controller) active.current = null
    }
  }

  const decidePlan = async (action: 'accept' | 'reject') => {
    if (!plan || !reason.trim()) { setMessage({ kind: 'error', text: '请填写操作原因' }); return }
    setBusy(true); setMessage(null)
    let outcome: Message
    try {
      const result = await decideResponsePlan(plan.plan_id, action, plan.current_revision, reason.trim())
      outcome = { kind: 'success', text: `${action === 'accept' ? '计划已接受' : '计划已拒绝'}：${result.status}` }
    } catch (error) { outcome = { kind: 'error', text: errorMessage(error) } }
    setMessage(await refreshAfterMutation(outcome))
    setBusy(false)
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
    <section aria-labelledby="tools-title" className={`page-card tools-page${embedded ? ' tools-page--embedded' : ''}`}>
      {!embedded && <><PageHeader id="tools-title" eyebrow="可信执行边界" title="处置中心" description="按服务端策略、风险和状态审核处置调用；执行与验证结果只以公开可信投影为准。" />
      <p className="tools-privacy">仅展示策略、审批、执行尝试、验证结果与证据引用；不展示原始结果、凭据或私有推理。</p></>}
      <div className="tools-control-panel">
        {!embedded && <form className="tools-form" onSubmit={(event) => void load(event)}>
          <label htmlFor="tool-run-id">调查运行 ID</label>
          <div>
            <input id="tool-run-id" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            <button disabled={busy || !runId.trim()}>查看处置轨迹</button>
          </div>
        </form>}
        {embedded && <div className="tools-embedded-context"><span>当前报告运行</span><code>{runId}</code><button className="secondary-button" disabled={busy} type="button" onClick={() => void load()}>刷新处置状态</button></div>}
        <label className="tools-reason" htmlFor="tool-action-reason">操作原因</label>
        <input id="tool-action-reason" className="tools-reason-input" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={512} />
        <div className="tools-emergency" aria-label="全局自动化控制">
          <button className="danger-button" disabled={busy} type="button" onClick={() => void emergency(true)}>紧急停止自动化</button>
          <button disabled={busy} type="button" onClick={() => void emergency(false)}>恢复自动化</button>
        </div>
        <p className="tools-control-note">紧急停止只阻止尚未下发的调用；执行中与验证中的动作必须继续查询和核验。</p>
      </div>

      {message && <p aria-live="polite" role={message.kind === 'error' ? 'alert' : 'status'} className={`tools-message tools-message--${message.kind}`}>{message.text}</p>}
      {partialErrors.length > 0 && partialErrors.length < 3 && <div className="tools-partial" role="status"><strong>部分公开数据暂不可用</strong><ul>{partialErrors.map((error) => <li key={error}>{error}</li>)}</ul></div>}
      <ol className="tools-safety-stages" aria-label="响应安全阶段">
        <li><strong>1. 建议</strong><span>结构化计划，不代表授权</span></li>
        <li><strong>2. 接受与审批</strong><span>接受计划不等于批准高风险动作</span></li>
        <li><strong>3. 执行</strong><span>仅服务端策略允许的绑定调用</span></li>
        <li><strong>4. 验证</strong><span>只有可信回执核验通过才算完成</span></li>
      </ol>
      {busy && !trace && !plan && !mcpCalls && <LoadingState title="正在读取处置轨迹" detail="正在从服务端刷新计划、MCP、策略、执行与验证状态。" />}
      {!busy && !trace && !plan && !mcpCalls && !message && <EmptyState title="尚未加载处置轨迹" detail="输入调查运行 ID，查看响应计划和可信工具调用。" />}

      {plan && <section className="response-plan" aria-labelledby="response-plan-title">
        <header><div><p className="eyebrow">建议与执行映射</p><h3 id="response-plan-title">响应计划 · 修订 {plan.current_revision}</h3></div><span className="status-badge">{plan.status}</span></header>
        {(() => {
          const current = plan.revisions.find((item) => item.revision === plan.current_revision)
          if (!current) return <p role="alert">当前修订缺少公开投影，不能执行操作。</p>
          return <>
            <p>{current.public_summary}</p>
            {current.reason_code && <p><strong>重规划/停止原因：</strong><code>{current.reason_code}</code></p>}
            {current.actions.length === 0 ? <EmptyState title="当前修订没有可执行动作" detail="失败修订只保留停止与人工复核事实，不自动生成或重放动作。" /> : <ol className="response-plan__actions">{current.actions.map((action) => <li key={action.id}>
              <header><strong>{action.sequence}. {action.tool_name} v{action.tool_version}</strong><span>风险 {action.assessed_risk}</span></header>
              <p>{action.public_reason}</p>
              <dl><div><dt>目标</dt><dd>{action.target_type} · <code>{action.target}</code></dd></div><div><dt>计划接受</dt><dd>{plan.status === 'proposed' ? '尚未接受' : '已决策'}</dd></div><div><dt>独立工具审批</dt><dd>{action.approval_required ? (action.call_status === 'awaiting_approval' ? '等待审批' : '必须审批') : '无需独立审批'}</dd></div><div><dt>执行</dt><dd>{action.call_status ?? '尚未创建调用'}</dd></div><div><dt>验证</dt><dd>{action.verification_outcome ?? '尚未验证'}</dd></div></dl>
              <small>动作 ID：<code>{action.id}</code>{action.call_id && <> · 调用 ID：<code>{action.call_id}</code></>}</small>
            </li>)}</ol>}
          </>
        })()}
        {plan.status === 'proposed' && <footer><button disabled={busy || !reason.trim()} type="button" onClick={() => void decidePlan('accept')}>接受计划并进入逐动作策略</button><button className="secondary-button" disabled={busy || !reason.trim()} type="button" onClick={() => void decidePlan('reject')}>拒绝计划</button></footer>}
        <p className="tools-control-note">接受只允许计划进入服务端逐动作策略；高风险动作仍需单独审批。页面不会提交工具名、参数、风险或策略字段。</p>
      </section>}

      {mcpCalls && <section className="mcp-run-calls" aria-labelledby="mcp-run-calls-title"><div className="tools-trace-heading"><div><p className="eyebrow">只读数据获取</p><h3 id="mcp-run-calls-title">Agent Tool / MCP 调用</h3></div><strong>{mcpCalls.length} 个调用</strong></div>{mcpCalls.length === 0 ? <p>该运行没有 Agent Tool/MCP 调用。</p> : <div>{mcpCalls.map((call) => <article key={call.id}><header><strong>{call.tool_alias}</strong><span className="status-badge">{call.status}</span></header><dl><div><dt>来源</dt><dd>{call.provider_kind === 'remote_mcp' ? '外部 MCP' : call.provider_kind === 'rag' ? '本地 RAG' : '内置只读工具'}</dd></div><div><dt>目录修订</dt><dd><code>{call.catalog_revision}</code></dd></div><div><dt>Schema 修订</dt><dd><code>{call.schema_revision}</code></dd></div><div><dt>结果</dt><dd>{call.result_count} 项{call.truncated ? ' · 已截断' : ''}</dd></div></dl><p>{call.summary ?? '调用尚未形成公开摘要。'}</p>{call.reason_code && <code>{call.reason_code}</code>}</article>)}</div>}</section>}
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
