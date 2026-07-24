import { useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import type { InvestigationMode, InvestigationResponse, InvestigationStatus, JsonObject } from './types'
import { useInvestigation } from './useInvestigation'
import './investigation.css'

const STATUS_LABELS: Partial<Record<InvestigationStatus, string>> = {
  closed: '已闭环',
  failed: '处置失败',
  needs_review: '需要人工复核',
  interrupted: '调查已中断',
}

function JsonDetails({ value }: { value: JsonObject }) {
  return <code>{JSON.stringify(value)}</code>
}

function RunResult({ run }: { run: InvestigationResponse }) {
  const verifiedClosed = run.status === 'closed'
    && run.verification?.blocked === true
    && run.verification.connection_stopped === true
  const publicStatus = verifiedClosed
    ? STATUS_LABELS.closed
    : run.status === 'closed' ? '闭环未验证' : STATUS_LABELS[run.status] ?? run.status
  const statusClass = verifiedClosed ? 'closed' : run.status === 'closed' ? 'unverified' : run.status

  return (
    <div className="investigation-result">
      <p className={`run-status run-status--${statusClass}`} aria-live="polite">{publicStatus}</p>
      {run.verification?.connection_stopped === true && <p>连接已停止</p>}

      {run.steps.length > 0 && (
        <section aria-labelledby="steps-title">
          <h3 id="steps-title">调查时间线</h3>
          <ol>{run.steps.map((step) => <li key={step.step_key}><strong>{step.step_key}</strong> · {step.status}</li>)}</ol>
        </section>
      )}

      {run.evidence.length > 0 && (
        <section aria-labelledby="evidence-title">
          <h3 id="evidence-title">证据</h3>
          <ul className="detail-list">{run.evidence.map((item) => {
            return (
              <li key={item.id}>
                <strong>{item.summary}</strong>
                <span>{item.source}</span>
                <span>{item.confidence}</span>
                <span>{item.integrity_verified ? '完整性已校验' : '完整性校验失败'}</span>
              </li>
            )
          })}</ul>
        </section>
      )}

      {run.assessment && (
        <section aria-labelledby="assessment-title">
          <h3 id="assessment-title">分析结论</h3>
          <p>{run.assessment.conclusion}</p>
          <p>{run.assessment.explanation}</p>
        </section>
      )}

      {run.tool_result && (
        <section aria-labelledby="tool-title">
          <h3 id="tool-title">处置结果</h3>
          <dl>
            <dt>目标</dt><dd>{run.tool_result.target}</dd>
            <dt>幂等键</dt><dd>{run.tool_result.idempotency_key}</dd>
            <dt>处置前</dt><dd><JsonDetails value={run.tool_result.before_state} /></dd>
            <dt>处置后</dt><dd><JsonDetails value={run.tool_result.after_state} /></dd>
            <dt>结果</dt><dd>{run.tool_result.status}</dd>
            {run.tool_result.error_code && <><dt>错误代码</dt><dd>{run.tool_result.error_code}</dd></>}
          </dl>
        </section>
      )}
    </div>
  )
}

export interface InvestigationPageProps {
  allowFailureMode?: boolean
}

const production = (import.meta as ImportMeta & { env?: { PROD?: boolean } }).env?.PROD === true

export function InvestigationPage({ allowFailureMode = !production }: InvestigationPageProps) {
  const [mode, setMode] = useState<InvestigationMode>('normal')
  const context = useRunContext()
  const state = useInvestigation({
    selectedRunId: context.runId,
    onRunSelected: (incidentId, runId) => context.setSelection({ incidentId, runId }),
  })

  return (
    <section aria-labelledby="investigation-title" className="page-card investigation-page">
      <p className="eyebrow">模拟环境</p>
      <h2 id="investigation-title">事件调查</h2>

      {state.scenario && (
        <p className="simulation-badge">模拟环境 · #{state.scenario.simulation.generation}</p>
      )}

      <div className="investigation-controls">
        <label htmlFor="investigation-mode">调查模式</label>
        <select
          id="investigation-mode"
          value={mode}
          disabled={state.active}
          onChange={(event) => setMode(event.target.value as InvestigationMode)}
        >
          <option value="normal">normal</option>
          {allowFailureMode && <option value="fail_block_once">fail_block_once</option>}
        </select>
        <button type="button" disabled={state.active} onClick={() => void state.start(mode)}>启动调查</button>
        <button type="button" disabled={state.active} onClick={() => void state.reset()}>重置场景</button>
      </div>

      {state.error && <p className="investigation-error" role="alert">{state.error}</p>}
      {state.run && <RunResult run={state.run} />}

      {state.incident && (
        <section aria-labelledby="incident-title">
          <h3 id="incident-title">事件</h3>
          <p>{state.incident.incident.external_id}</p>
          <p>{state.incident.incident.remote_ip}:{state.incident.incident.remote_port}</p>
        </section>
      )}

      {state.audit && state.audit.events.length > 0 && (
        <section aria-labelledby="audit-title">
          <h3 id="audit-title">审计记录</h3>
          <ol>{[...state.audit.events].sort((left, right) => left.sequence - right.sequence).map((event) => (
            <li key={event.id}><strong>{event.event_type}</strong> · {event.occurred_at}</li>
          ))}</ol>
        </section>
      )}
    </section>
  )
}
