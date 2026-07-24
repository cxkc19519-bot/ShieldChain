import { type FormEvent, useEffect, useState } from 'react'

import { useRunContext } from './RunContext'

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
      <label htmlFor="context-incident-id">事件 ID</label>
      <input id="context-incident-id" value={incidentId} onChange={(event) => setIncidentId(event.target.value)} placeholder="事件 UUID" />
      <label htmlFor="context-run-id">运行 ID</label>
      <input id="context-run-id" value={runId} onChange={(event) => setRunId(event.target.value)} placeholder="运行 UUID" />
      <div>
        <button type="submit">应用上下文</button>
        <button type="button" className="button-secondary" onClick={() => context.clearSelection()}>清除</button>
      </div>
    </form>
  )
}
