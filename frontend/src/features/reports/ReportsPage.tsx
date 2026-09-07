import { useCallback, useEffect, useRef, useState } from 'react'

import { ToolsPage } from '../tools/ToolsPage'
import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, LoadingState } from '../../components/ui/States'
import { deleteHistoricalReport, listHistoricalReports, loadReportBundle } from './api'
import type { HistoricalReport, ReportBundle } from './types'
import './reports.css'

type WorkspaceView = 'details' | 'operations'

const STATUS_LABELS: Record<string, string> = {
  pending: '等待调查', collecting: '正在收集证据', analyzing: '正在研判证据',
  action_planned: '已生成处置方案', executing: '正在执行处置', verifying: '正在验证处置效果',
  closed: '已闭环', failed: '处置失败', needs_review: '需要人工复核', interrupted: '调查已中断',
}

const CONCLUSION_LABELS: Record<string, string> = {
  confirmed_threat: '已确认威胁',
  insufficient_evidence: '证据不足',
}

const RISK_LABELS: Record<string, string> = {
  high: '高风险',
  unknown: '风险待确认',
}

const AUDIT_EVENT_LABELS: Record<string, string> = {
  simulation_reset: '模拟场景已重置',
  run_created: '调查运行已创建',
  status_changed: '调查状态已更新',
  evidence_collected: '证据已收集',
  assessment_completed: '研判已完成',
  verification_completed: '处置验证已完成',
}

const AGENT_ROLE_LABELS: Record<string, string> = {
  superagent: '总控智能体',
  alert_triage: '告警分诊智能体',
  threat_investigation: '威胁研判智能体',
  knowledge_retrieval: '知识检索智能体',
  response_planning: '响应规划智能体',
  verification: '验证智能体',
  reporting: '报告智能体',
}

const AGENT_STATUS_LABELS: Record<string, string> = {
  completed: '已完成',
  not_started: '未启动',
  needs_review: '需要人工复核',
  dependency_unavailable: '依赖暂不可用',
  failed: '执行失败',
}
const EXPLANATION_LABELS: Record<string, string> = {
  'Evidence is incomplete, malformed, conflicting, or does not match all rules.': '证据不完整、格式异常、相互矛盾，或未能满足全部研判规则。',
}

function chineseLabel(value: string | null | undefined, labels: Record<string, string>, fallback: string): string {
  return value ? (labels[value] ?? fallback) : fallback
}

function chineseExplanation(value: string): string {
  if (/[\u4e00-\u9fff]/.test(value)) return value
  return EXPLANATION_LABELS[value] ?? '该调查结论需要结合证据链进一步复核。'
}
function reportError(value: unknown, fallback: string): string {
  const message = value instanceof Error ? value.message : ''
  return /[\u4e00-\u9fff]/.test(message) ? message : fallback
}

function dateTime(value: string | null): string {
  if (!value) return '尚未结束'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false })
}

function status(value: string): string {
  return STATUS_LABELS[value] ?? '状态待确认'
}

function ReportSummary({ bundle }: { bundle: ReportBundle }) {
  const audit = [...(bundle.audit?.events ?? [])].sort((left, right) => left.sequence - right.sequence)
  const investigation = bundle.investigation
  const assessment = investigation?.assessment
  return <div className="report-detail-summary">
    <section className="report-summary-card report-summary-card--overview">
      <header><div><p className="eyebrow">研判概览</p><h3>调查摘要</h3></div>{investigation && <span className="report-state-pill">{status(investigation.status)}</span>}</header>
      {investigation ? <><dl className="report-overview-grid"><div><dt>研判结论</dt><dd>{chineseLabel(assessment?.conclusion, CONCLUSION_LABELS, '尚未形成结论')}</dd></div><div><dt>风险等级</dt><dd>{chineseLabel(assessment?.risk_level, RISK_LABELS, '待确认')}</dd></div><div><dt>验证结果</dt><dd>{investigation.verification?.blocked ? '目标已阻断' : '尚未完成阻断验证'}</dd></div></dl>{assessment?.explanation && <div className="report-explanation"><span>研判说明</span><p>{chineseExplanation(assessment.explanation)}</p></div>}</> : <p className="report-unavailable">调查公开投影暂不可用。</p>}
    </section>
    <section className="report-summary-card report-summary-card--audit">
      <header><div><p className="eyebrow">可追溯记录</p><h3>审计记录</h3></div><span className="report-count">{audit.length} 项</span></header>
      {audit.length ? <ol className="report-audit">{audit.map((event) => <li data-testid="audit-event" key={event.id}><span>{event.sequence}</span><div><strong>{chineseLabel(event.event_type, AUDIT_EVENT_LABELS, '其他审计事件')}</strong><p>{dateTime(event.occurred_at)}</p></div></li>)}</ol> : <p className="report-unavailable">暂无公开审计记录。</p>}
    </section>
    <section className="report-summary-card report-summary-card--trajectory">
      <header><div><p className="eyebrow">多智能体协同</p><h3>智能体协作</h3></div></header>
      {bundle.collaboration ? <><p className="report-trajectory-summary">{bundle.collaboration.shared_summary}</p><dl className="report-detail-list"><dt>当前阶段</dt><dd>{chineseLabel(bundle.collaboration.phase, { response_planning: '响应规划', needs_review: '人工复核' }, '协作处理中')}</dd><dt>协作修订</dt><dd>第 {bundle.collaboration.revision} 版</dd><dt>已确认事实</dt><dd>{bundle.collaboration.confirmed_facts.length} 条</dd></dl><div className="report-agent-statuses">{bundle.collaboration.role_statuses.filter((role) => role.status !== 'not_started').map((role) => <article key={role.role}><div><strong>{chineseLabel(role.role, AGENT_ROLE_LABELS, '专业智能体')}</strong><span>{chineseLabel(role.status, AGENT_STATUS_LABELS, '状态待确认')}</span></div>{role.summary && <p>{role.summary}</p>}{role.role === 'knowledge_retrieval' && <small>已自动触发知识库 RAG 检索</small>}</article>)}</div></> : <p className="report-unavailable">该运行尚未生成公开智能体协作轨迹。</p>}
    </section>
    <section className="report-summary-card report-summary-card--trajectory">
      <header><div><p className="eyebrow">受控决策记录</p><h3>ReAct 工作台</h3></div></header>
      {bundle.react ? <><dl className="report-detail-list"><dt>循环状态</dt><dd>{bundle.react.status}</dd><dt>当前修订</dt><dd>第 {bundle.react.revision} 版</dd><dt>公开决策</dt><dd>{bundle.react.decisions.length} 条</dd></dl><div className="report-decisions">{bundle.react.decisions.slice(-3).map((decision) => <p key={decision.id}><strong>{decision.decision}</strong><span>{decision.reason_code}</span></p>)}</div></> : <p className="report-unavailable">该运行尚未生成公开 ReAct 轨迹。</p>}
    </section>
  </div>
}
export function ReportsPage() {
  const [reports, setReports] = useState<HistoricalReport[]>([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState<string | null>(null)
  const [selected, setSelected] = useState<HistoricalReport | null>(null)
  const [view, setView] = useState<WorkspaceView>('details')
  const [bundle, setBundle] = useState<ReportBundle | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState<string | null>(null)
  const [deletingRunId, setDeletingRunId] = useState<string | null>(null)
  const historyRequest = useRef<AbortController | null>(null)
  const detailRequest = useRef<AbortController | null>(null)
  const workspace = useRef<HTMLElement | null>(null)

  const refreshHistory = useCallback(async () => {
    historyRequest.current?.abort()
    const controller = new AbortController()
    historyRequest.current = controller
    setHistoryLoading(true)
    setHistoryError(null)
    try {
      const items = await listHistoricalReports(controller.signal)
      if (!controller.signal.aborted) setReports(items)
    } catch (reason) {
      if (!controller.signal.aborted) setHistoryError(reportError(reason, '历史报告加载失败，请稍后重试。'))
    } finally {
      if (historyRequest.current === controller) historyRequest.current = null
      if (!controller.signal.aborted) setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    void refreshHistory()
    return () => historyRequest.current?.abort()
  }, [refreshHistory])

  useEffect(() => {
    detailRequest.current?.abort()
    setBundle(null)
    setDetailError(null)
    if (!selected || view !== 'details') { setDetailLoading(false); return }
    const controller = new AbortController()
    detailRequest.current = controller
    setDetailLoading(true)
    void loadReportBundle({ incidentId: selected.incident_id, runId: selected.run_id }, controller.signal)
      .then((result) => { if (!controller.signal.aborted) setBundle(result) })
      .catch((reason) => { if (!controller.signal.aborted) setDetailError(reportError(reason, '报告详情加载失败，请稍后重试。')) })
      .finally(() => { if (detailRequest.current === controller) detailRequest.current = null; if (!controller.signal.aborted) setDetailLoading(false) })
    return () => controller.abort()
  }, [selected, view])

  const select = (report: HistoricalReport, nextView: WorkspaceView) => {
    setSelected(report)
    setView(nextView)
  }

  const remove = async (report: HistoricalReport) => {
    const confirmed = window.confirm(`确定删除“${report.incident_tracking_id}”吗？此操作会永久删除本地保存的调查、事件、审计和处置记录，无法恢复。`)
    if (!confirmed) return
    setDeletingRunId(report.run_id)
    setHistoryError(null)
    try {
      await deleteHistoricalReport(report.run_id)
      setReports((items) => items.filter((item) => item.run_id !== report.run_id))
      if (selected?.run_id === report.run_id) setSelected(null)
    } catch (reason) {
      setHistoryError(reportError(reason, '删除历史报告失败，请稍后重试。'))
    } finally {
      setDeletingRunId(null)
    }
  }
  useEffect(() => {
    if (!selected) return
    if (typeof workspace.current?.scrollIntoView === 'function') {
      workspace.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [selected, view])

  return <section aria-labelledby="reports-title" className="page-card reports-page">
    <PageHeader id="reports-title" eyebrow="调查记录与受控处置" title="历史报告" description="集中查看历史调查报告；详情展示调查、审计、智能体协作与 ReAct 公开轨迹，操作区提供可信处置控制。" actions={<button disabled={historyLoading} type="button" onClick={() => void refreshHistory()}>刷新列表</button>} />

    {historyError && <p className="report-error" role="alert">{historyError}</p>}
    {historyLoading && reports.length === 0 && <LoadingState title="正在加载历史报告" detail="正在读取可追溯的调查运行记录。" />}
    {!historyLoading && reports.length === 0 && !historyError && <EmptyState title="暂无历史报告" detail="启动一次事件调查后，报告会自动保留在这里。" />}

    {selected && <section ref={workspace} tabIndex={-1} aria-labelledby="report-workspace-title" className="report-workspace">
      <header className="report-workspace__header"><div><p className="eyebrow">{selected.incident_tracking_id} · {selected.run_tracking_id}</p><h3 id="report-workspace-title">{view === 'details' ? '报告详情' : '报告处置操作'}</h3></div><div><button className="secondary-button" type="button" onClick={() => setSelected(null)}>返回历史报告</button><button className={view === 'details' ? '' : 'secondary-button'} type="button" onClick={() => setView('details')}>查看详情</button><button className={view === 'operations' ? '' : 'secondary-button'} type="button" onClick={() => setView('operations')}>操作</button></div></header>
      {view === 'details' && <>
        {detailLoading && <LoadingState title="正在加载报告详情" detail="正在读取调查、审计、智能体与 ReAct 的公开投影。" />}
        {detailError && <p className="report-error" role="alert">{detailError}</p>}
        {bundle && <ReportSummary bundle={bundle} />}
      </>}
      {view === 'operations' && <div className="report-operation">
        <div className="report-operation__intro"><div><p className="eyebrow">人工确认与可信执行</p><h4>处置工作台</h4><p>所有操作都会记录在该报告对应的可信处置轨迹中。</p></div><dl><div><dt>处置对象</dt><dd>{selected.endpoint}</dd></div><div><dt>运行编号</dt><dd>{selected.run_tracking_id}</dd></div></dl></div>
        <ToolsPage key={`tools-${selected.run_id}`} initialRunId={selected.run_id} embedded />
      </div>}
    </section>}

    {!selected && reports.length > 0 && <section aria-labelledby="history-list-title" className="report-history">
      <div className="report-section-heading"><div><p className="eyebrow">可追溯记录</p><h3 id="history-list-title">历史调查报告</h3></div><span>{reports.length} 条</span></div>
      <div className="report-history__table" role="list">
        {reports.map((report) => <article key={report.run_id} role="listitem" className=''>
          <div><strong>{report.incident_tracking_id}</strong><span>{report.run_tracking_id}</span></div>
          <div><span>{report.endpoint}</span><small>{report.threat_label}</small></div>
          <div><span className="status-badge">{status(report.status)}</span><small>更新于 {dateTime(report.updated_at)}</small></div>
          <div className="report-history__actions"><button type="button" onClick={() => select(report, 'details')}>查看详情</button><button type="button" className="secondary-button" onClick={() => select(report, 'operations')}>操作</button><button type="button" className="danger-button" disabled={deletingRunId === report.run_id} onClick={() => void remove(report)}>{deletingRunId === report.run_id ? '正在删除…' : '删除记录'}</button></div>
        </article>)}
      </div>
    </section>}
  </section>
}