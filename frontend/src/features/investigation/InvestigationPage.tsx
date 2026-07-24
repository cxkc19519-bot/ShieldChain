import { useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { EmptyState } from '../../components/ui/States'
import { PageHeader } from '../../components/ui/PageHeader'
import { StatusBadge } from '../../components/ui/StatusBadge'
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
      <header className="investigation-result__header">
        <div><span>运行状态</span><p className={`run-status run-status--${statusClass}`} aria-live="polite">{publicStatus}</p></div>
        <code>{run.run_id}</code>
      </header>

      {run.steps.length > 0 && (
        <section className="investigation-section" aria-labelledby="steps-title">
          <h3 id="steps-title">调查阶段</h3>
          <ol className="phase-track">{run.steps.map((step) => <li key={step.step_key}><StatusBadge tone={step.status === 'completed' ? 'success' : 'info'}>{step.status}</StatusBadge><strong>{step.step_key}</strong>{step.error_code && <code>{step.error_code}</code>}</li>)}</ol>
        </section>
      )}

      {run.evidence.length > 0 && (
        <section className="investigation-section" aria-labelledby="evidence-title">
          <h3 id="evidence-title">证据链</h3>
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
        <section className="investigation-section" aria-labelledby="assessment-title">
          <h3 id="assessment-title">研判结论</h3>
          <StatusBadge tone={run.assessment.risk_level === 'high' || run.assessment.risk_level === 'critical' ? 'danger' : 'warning'}>{run.assessment.risk_level}</StatusBadge>
          <p>{run.assessment.conclusion}</p>
          <p>{run.assessment.explanation}</p>
        </section>
      )}

      {run.tool_result && (
        <section className="investigation-section" aria-labelledby="tool-title">
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

      <section className="investigation-section" aria-labelledby="verification-title">
        <h3 id="verification-title">验证</h3>
        {!run.verification && <p>尚无验证结果。</p>}
        {run.verification && <div className="verification-grid"><span>{run.verification.blocked ? '目标已阻断' : '目标未阻断'}</span><span>{run.verification.connection_stopped ? '连接已停止' : '连接未停止'}</span><span>{run.verification.evidence_ids.length} 条验证证据</span></div>}
      </section>
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
  const activeIncident = state.incident?.incident ?? state.scenario?.incident

  return (
    <section aria-labelledby="investigation-title" className="page-card investigation-page">
      <PageHeader id="investigation-title" eyebrow="模拟环境" title="事件调查" description="沿公开投影追踪攻击路径、证据、研判、受控处置、验证和审计记录。" />

      {state.scenario && (
        <div className="simulation-badge"><StatusBadge tone="info">离线仿真</StatusBadge><span>场景代次 #{state.scenario.simulation.generation}</span></div>
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

      {activeIncident && (
        <section className="incident-overview" aria-labelledby="incident-title">
          <header><div><span>当前事件</span><h3 id="incident-title">{activeIncident.external_id}</h3></div><StatusBadge tone="danger">{activeIncident.threat_label}</StatusBadge></header>
          <div className="attack-path" aria-label="攻击路径">
            <div><span>终端</span><strong>{activeIncident.endpoint}</strong><small>{activeIncident.username}</small></div>
            <span aria-hidden="true">→</span>
            <div><span>进程</span><strong>{activeIncident.process_name}</strong><small>父进程 {activeIncident.parent_process_name}</small></div>
            <span aria-hidden="true">→</span>
            <div><span>远端</span><strong>{activeIncident.remote_ip}:{activeIncident.remote_port}</strong><small>{activeIncident.command_summary}</small></div>
          </div>
        </section>
      )}

      {!state.run && !state.pending && <EmptyState title="尚未启动调查" detail="选择调查模式后启动离线仿真；失败模式仅用于非生产测试。" />}
      {state.run && <RunResult run={state.run} />}

      {state.audit && state.audit.events.length > 0 && (
        <section className="investigation-section" aria-labelledby="audit-title">
          <h3 id="audit-title">审计时间线</h3>
          <ol className="audit-timeline">{[...state.audit.events].sort((left, right) => left.sequence - right.sequence).map((event) => (
            <li key={event.id}><strong>{event.event_type}</strong> · {event.occurred_at}</li>
          ))}</ol>
        </section>
      )}
    </section>
  )
}
