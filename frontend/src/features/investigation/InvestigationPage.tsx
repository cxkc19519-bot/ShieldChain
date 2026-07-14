import { useState } from 'react'

import type { InvestigationMode, InvestigationResponse, InvestigationStatus, JsonObject } from './types'
import { useInvestigation } from './useInvestigation'
import './investigation.css'

const STATUS_LABELS: Partial<Record<InvestigationStatus, string>> = {
  closed: '宸查棴鐜痐',
  failed: '澶勭疆澶辫触',
  needs_review: '闇€瑕佷汉宸ュ鏍竊',
  interrupted: '璋冩煡宸蹭腑鏂璥',
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
    : run.status === 'closed' ? 'closed' : STATUS_LABELS[run.status] ?? run.status
  const statusClass = verifiedClosed ? 'closed' : run.status === 'closed' ? 'unverified' : run.status

  return (
    <div className="investigation-result">
      <p className={`run-status run-status--${statusClass}`} aria-live="polite">{publicStatus}</p>
      {run.verification?.connection_stopped === true && <p>杩炴帴宸插仠姝</p>}

      {run.steps.length > 0 && (
        <section aria-labelledby="steps-title">
          <h3 id="steps-title">调查时间线</h3>
          <ol>{run.steps.map((step) => <li key={step.step_key}><strong>{step.step_key}</strong> · {step.status}</li>)}</ol>
        </section>
      )}

      {run.evidence.length > 0 && (
        <section aria-labelledby="evidence-title">
          <h3 id="evidence-title">璇佹嵁</h3>
          <ul className="detail-list">{run.evidence.map((item) => {
            const integrityPresent = item.confirmed && /^[0-9a-f]{64}$/.test(item.integrity_sha256)
            return (
              <li key={item.id}>
                <strong>{item.summary}</strong>
                <span>{item.source}</span>
                <span>{item.confidence}</span>
                {integrityPresent && <span>瀹屾暣鎬у凡鏍￠獙</span>}
              </li>
            )
          })}</ul>
        </section>
      )}

      {run.assessment && (
        <section aria-labelledby="assessment-title">
          <h3 id="assessment-title">鍒嗘瀽缁撹</h3>
          <p>{run.assessment.conclusion}</p>
          <p>{run.assessment.explanation}</p>
        </section>
      )}

      {run.tool_result && (
        <section aria-labelledby="tool-title">
          <h3 id="tool-title">澶勭疆缁撴灉</h3>
          <dl>
            <dt>鐩爣</dt><dd>{run.tool_result.target}</dd>
            <dt>幂等键</dt><dd>{run.tool_result.idempotency_key}</dd>
            <dt>处置前</dt><dd><JsonDetails value={run.tool_result.before_state} /></dd>
            <dt>处置后</dt><dd><JsonDetails value={run.tool_result.after_state} /></dd>
            <dt>缁撴灉</dt><dd>{run.tool_result.status}</dd>
            {run.tool_result.error_code && <><dt>閿欒浠ｇ爜</dt><dd>{run.tool_result.error_code}</dd></>}
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
  const state = useInvestigation()

  return (
    <section aria-labelledby="investigation-title" className="page-card investigation-page">
      <p className="eyebrow">妯℃嫙鐜</p>
      <h2 id="investigation-title">浜嬩欢璋冩煡</h2>

      {state.scenario && (
        <p className="simulation-badge">妯℃嫙鐜 · #{state.scenario.simulation.generation}</p>
      )}

      <div className="investigation-controls">
        <label htmlFor="investigation-mode">璋冩煡妯″紡</label>
        <select
          id="investigation-mode"
          value={mode}
          disabled={state.active}
          onChange={(event) => setMode(event.target.value as InvestigationMode)}
        >
          <option value="normal">normal</option>
          {allowFailureMode && <option value="fail_block_once">fail_block_once</option>}
        </select>
        <button type="button" disabled={state.active} onClick={() => void state.start(mode)}>鍚姩璋冩煡</button>
        <button type="button" disabled={state.active} onClick={() => void state.reset()}>閲嶇疆鍦烘櫙</button>
      </div>

      {state.error && <p className="investigation-error" role="alert">{state.error}</p>}
      {state.run && <RunResult run={state.run} />}

      {state.incident && (
        <section aria-labelledby="incident-title">
          <h3 id="incident-title">浜嬩欢</h3>
          <p>{state.incident.incident.external_id}</p>
          <p>{state.incident.incident.remote_ip}:{state.incident.incident.remote_port}</p>
        </section>
      )}

      {state.audit && state.audit.events.length > 0 && (
        <section aria-labelledby="audit-title">
          <h3 id="audit-title">瀹¤璁板綍</h3>
          <ol>{[...state.audit.events].sort((left, right) => left.sequence - right.sequence).map((event) => (
            <li key={event.id}><strong>{event.event_type}</strong> · {event.occurred_at}</li>
          ))}</ol>
        </section>
      )}
    </section>
  )
}
