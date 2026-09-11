import { type FormEvent, useEffect, useState } from 'react'

import { useRunContext } from './RunContext'

function compactTrackingId(prefix: string, id: string | null): string | null {
  return id ? `${prefix}-${id.slice(0, 8).toUpperCase()}` : null
}

export function RunContextSwitcher() {
  const context = useRunContext()
  const [incidentId, setIncidentId] = useState(context.incidentId ?? '')
  const [runId, setRunId] = useState(context.runId ?? '')

  useEffect(() => setIncidentId(context.incidentId ?? ''), [context.incidentId])
  useEffect(() => setRunId(context.runId ?? ''), [context.runId])

  const apply = (event: FormEvent) => {
    event.preventDefault()
    context.setSelection({ incidentId, runId })
  }

  return (
    <form className="run-context" aria-label="当前案件与运行" onSubmit={apply}>
      <strong>当前追踪上下文</strong>
      {(context.incidentId || context.runId) && <p className="run-context__summary">当前：{compactTrackingId('INC', context.incidentId) ?? '未选事件'} · {compactTrackingId('RUN', context.runId) ?? '未选运行'}</p>}
      <details className="run-context__advanced">
        <summary>高级：手动输入内部 UUID</summary>
        <label htmlFor="context-incident-id">事件内部 ID</label>
        <input id="context-incident-id" aria-label="事件 ID" value={incidentId} onChange={(event) => setIncidentId(event.target.value)} placeholder="事件 UUID" />
        <label htmlFor="context-run-id">运行内部 ID</label>
        <input id="context-run-id" aria-label="运行 ID" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="运行 UUID" />
      </details>
      <div>
        <button type="submit">应用上下文</button>
        <button type="button" className="button-secondary" onClick={() => context.clearSelection()}>清除</button>
      </div>
    </form>
  )
}
