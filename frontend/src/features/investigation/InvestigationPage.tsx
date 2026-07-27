import { useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { EmptyState } from '../../components/ui/States'
import { PageHeader } from '../../components/ui/PageHeader'
import { StatusBadge } from '../../components/ui/StatusBadge'
import type { InvestigationMode, InvestigationResponse, InvestigationStatus, JsonObject } from './types'
import { useInvestigation } from './useInvestigation'
import './investigation.css'

const STATUS_LABELS: Partial<Record<InvestigationStatus, string>> = {
  pending: '等待调查',
  collecting: '正在收集证据',
  analyzing: '正在研判证据',
  action_planned: '已生成处置方案',
  executing: '正在执行处置',
  verifying: '正在验证处置效果',
  closed: '已闭环',
  failed: '处置失败',
  needs_review: '需要人工复核',
  interrupted: '调查已中断',
}

const STEP_LABELS: Record<string, string> = {
  collect: '收集证据',
  collect_evidence: '收集证据',
  analyze: '研判证据',
  block_ip: '阻断恶意 IP',
  verify: '验证处置效果',
}

const STEP_STATUS_LABELS: Record<string, string> = {
  pending: '等待执行',
  running: '执行中',
  succeeded: '已完成',
  completed: '已完成',
  failed: '执行失败',
  skipped: '已跳过',
}

const EVIDENCE_SUMMARIES: Record<string, string> = {
  alert: '发现待处置的恶意威胁告警',
  network_connection: '可疑进程存在活跃外连',
  threat_intelligence: '目标 IP 已被识别为恶意',
  process: '终端发现可疑进程',
  parent_process: '可疑父进程启动了载荷',
  network: '发现可疑网络连接',
}

const EVIDENCE_SOURCES: Record<string, string> = {
  simulated_siem: '模拟安全信息与事件管理系统（SIEM）',
  simulated_edr: '模拟终端检测与响应系统（EDR）',
  simulated_ti: '模拟威胁情报系统',
  'simulation://network': '模拟网络遥测',
}

const CONCLUSION_LABELS: Record<string, string> = {
  confirmed_threat: '已确认安全威胁',
  insufficient_evidence: '证据不足，需人工复核',
}

const RISK_LABELS: Record<string, string> = {
  high: '高风险',
  unknown: '待确认',
}

const ASSESSMENT_EXPLANATIONS: Record<string, string> = {
  'Evidence is incomplete, malformed, conflicting, or does not match all rules.': '证据不完整、格式异常、相互冲突，或未满足全部研判规则。',
  'All five deterministic phishing rules matched consistent evidence.': '五项确定性钓鱼研判规则均与证据链一致。',
}

const AUDIT_EVENT_LABELS: Record<string, string> = {
  simulation_reset: '模拟场景已重置',
  run_created: '调查任务已创建',
  status_changed: '调查状态已更新',
  evidence_collected: '证据已收集',
  assessment_completed: '研判已完成',
  tool_called: '处置工具已调用',
  verification_completed: '处置验证已完成',
}

const TOOL_STATUS_LABELS: Record<string, string> = {
  blocked: '已阻断',
  already_blocked: '目标已处于阻断状态',
  failed: '阻断执行失败',
}

const ERROR_CODE_LABELS: Record<string, string> = {
  simulated_block_failure: '模拟阻断失败',
  invalid_investigation_state: '调查状态异常',
  unexpected_workflow_error: '调查工作流异常',
}

function label(value: string, labels: Record<string, string>, fallback: string): string {
  return labels[value] ?? fallback
}

function assessmentExplanation(value: string): string {
  return ASSESSMENT_EXPLANATIONS[value] ?? '系统未提供中文研判说明。'
}
function trackingRunLabel(run: InvestigationResponse): string {
  return run.run_tracking_id ?? `RUN-${run.run_id.slice(0, 8).toUpperCase()}`
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
    : run.status === 'closed' ? '闭环未验证' : STATUS_LABELS[run.status] ?? '状态未知'
  const statusClass = verifiedClosed ? 'closed' : run.status === 'closed' ? 'unverified' : run.status

  return (
    <div className="investigation-result">
      <header className="investigation-result__header">
        <div><span>运行状态</span><p className={`run-status run-status--${statusClass}`} aria-live="polite">{publicStatus}</p></div>
        <code title="内部 UUID 已隐藏">{trackingRunLabel(run)}</code>
      </header>

      {run.steps.length > 0 && (
        <section className="investigation-section" aria-labelledby="steps-title">
          <h3 id="steps-title">调查阶段</h3>
          <ol className="phase-track">{run.steps.map((step) => <li key={step.step_key}><StatusBadge tone={step.status === 'completed' || step.status === 'succeeded' ? 'success' : 'info'}>{label(step.status, STEP_STATUS_LABELS, '状态未知')}</StatusBadge><strong>{label(step.step_key, STEP_LABELS, '调查步骤')}</strong>{step.error_code && <code>{label(step.error_code, ERROR_CODE_LABELS, '执行异常')}</code>}</li>)}</ol>
        </section>
      )}

      {run.evidence.length > 0 && (
        <section className="investigation-section" aria-labelledby="evidence-title">
          <h3 id="evidence-title">证据链</h3>
          <ul className="detail-list">{run.evidence.map((item) => {
            return (
              <li key={item.id}>
                <strong>{label(item.evidence_type, EVIDENCE_SUMMARIES, '安全事件证据')}</strong>
                <span>{label(item.source, EVIDENCE_SOURCES, '系统遥测来源')}</span>
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
          <StatusBadge tone={run.assessment.risk_level === 'high' || run.assessment.risk_level === 'critical' ? 'danger' : 'warning'}>{label(run.assessment.risk_level, RISK_LABELS, '待确认')}</StatusBadge>
          <p>{label(run.assessment.conclusion, CONCLUSION_LABELS, '研判结果待确认')}</p>
          <p>{assessmentExplanation(run.assessment.explanation)}</p>
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
            <dt>结果</dt><dd>{label(run.tool_result.status, TOOL_STATUS_LABELS, '处置状态待确认')}</dd>
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
          <option value="normal">常规模式</option>
          {allowFailureMode && <option value="fail_block_once">异常模拟 (封禁失败)</option>}
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
            <li key={event.id}><strong>{label(event.event_type, AUDIT_EVENT_LABELS, '系统审计事件')}</strong> · {event.occurred_at}</li>
          ))}</ol>
        </section>
      )}
    </section>
  )
}
