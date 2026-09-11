import { useEffect, useState } from 'react'
import { ArrowUpRight, CheckCircle2, Network, Radar, ShieldCheck, Sparkles } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'

import { getLiveness } from '../../api/client'
import { useRunContext } from '../../app/RunContext'
import { PageHeader } from '../../components/ui/PageHeader'
import { ErrorState, LoadingState } from '../../components/ui/States'
import { StatusBadge } from '../../components/ui/StatusBadge'
import { getInvestigation } from '../investigation/api'
import type { InvestigationResponse } from '../investigation/types'
import { listOperationsReports, type OperationsReport } from '../operations/api'
import './dashboard.css'

type HealthState = 'loading' | 'healthy' | 'unavailable'

const statusLabels: Record<string, string> = {
  pending: '等待执行', collecting: '证据收集', analyzing: '分析中', action_planned: '已形成处置计划',
  executing: '处置执行中', verifying: '验证中', needs_review: '需要人工复核', failed: '调查失败',
  interrupted: '调查已中断', closed: '调查已闭环',
}

const riskLabels: Record<string, string> = { low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险' }

function resultLabel(run: InvestigationResponse): string {
  if (!run.tool_result) return '尚未执行'
  return run.tool_result.status === 'succeeded' ? '执行成功' : run.tool_result.status
}

function verificationLabel(run: InvestigationResponse): string {
  if (run.verification?.blocked && run.verification.connection_stopped) return '处置已验证'
  return run.verification ? '验证未通过' : '等待验证'
}

function isMissingInvestigation(failure: unknown): boolean {
  return typeof failure === 'object' && failure !== null
    && 'status' in failure && (failure as { status?: unknown }).status === 404
}

function Metric({ label, value }: { label: string; value: string }) {
  return <article className="dashboard-metric"><span>{label}</span><strong>{value}</strong></article>
}

function dateTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

export function DashboardPage() {
  const context = useRunContext()
  const location = useLocation()
  const [health, setHealth] = useState<HealthState>('loading')
  const [healthError, setHealthError] = useState<string | null>(null)
  const [healthAttempt, setHealthAttempt] = useState(0)
  const [runAttempt, setRunAttempt] = useState(0)
  const [run, setRun] = useState<InvestigationResponse | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [runLoading, setRunLoading] = useState(false)
  const [reports, setReports] = useState<OperationsReport[]>([])
  const [reportsLoading, setReportsLoading] = useState(true)
  const [reportsError, setReportsError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setHealth('loading')
    setHealthError(null)
    void getLiveness(controller.signal).then(
      () => {
        if (!controller.signal.aborted) {
          setHealth('healthy')
          setHealthError(null)
        }
      },
      (failure: unknown) => { 
        if (!controller.signal.aborted) {
          setHealth('unavailable')
          setHealthError(failure instanceof Error ? failure.message : String(failure))
        }
      },
    )
    return () => controller.abort()
  }, [healthAttempt])

  useEffect(() => {
    const controller = new AbortController()
    setReportsLoading(true)
    setReportsError(null)
    void listOperationsReports(controller.signal).then(
      (items) => { if (!controller.signal.aborted) setReports(items) },
      (failure: unknown) => {
        if (!controller.signal.aborted) setReportsError(failure instanceof Error ? failure.message : '运营记录暂不可用')
      },
    ).finally(() => { if (!controller.signal.aborted) setReportsLoading(false) })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    setRun(null)
    setRunError(null)
    if (!context.runId) {
      setRunLoading(false)
      return
    }
    const controller = new AbortController()
    setRunLoading(true)
    void getInvestigation(context.runId, controller.signal).then(
      (next) => {
        if (!controller.signal.aborted) {
          setRun(next)
          setRunError(null)
        }
      },
      (failure: unknown) => {
        if (controller.signal.aborted) return
        if (isMissingInvestigation(failure)) {
          context.clearSelection()
          return
        }
        setRunError(failure instanceof Error ? failure.message : '无法加载调查总览')
      },
    ).finally(() => { if (!controller.signal.aborted) setRunLoading(false) })
    return () => controller.abort()
  }, [context, context.runId, runAttempt])

  const confirmedEvidence = run?.evidence.filter((item) => item.confirmed && item.integrity_verified).length ?? 0
  const risk = run?.assessment?.risk_level
  const latestReport = reports[0] ?? null
  const closedReports = reports.filter((item) => item.closure.status === 'closed').length
  const automaticReports = reports.filter((item) => !item.closure.human_approval_required).length
  const verifiedActions = reports.reduce((total, item) => total + (item.response_plan?.execution_status === 'verified_completed' ? item.response_plan.action_count : 0), 0)
  const observedDomains = latestReport?.cross_domain.filter((item) => item.status === 'observed') ?? []
  const loopState = {
    observed: Boolean(latestReport),
    decided: Boolean(latestReport?.closure.decision),
    acted: (latestReport?.response_plan?.action_count ?? 0) > 0,
    verified: latestReport?.response_plan?.execution_status === 'verified_completed' || latestReport?.closure.status === 'closed',
  }

  return (
    <section aria-labelledby="dashboard-title" className="page-card dashboard-page">
      <PageHeader
        id="dashboard-title"
        title="运营总览"
        centered
      />

      <div className="dashboard-health" role="status" aria-live="polite">
        <div>
          <strong>控制面健康</strong>
          {health === 'loading' && <p>正在检查系统状态</p>}
          {health === 'healthy' && <p>系统运行正常</p>}
          {health === 'unavailable' && (
            <p>系统当前不可用 {healthError && <span style={{ color: 'var(--color-danger)', marginLeft: '0.5rem' }}>({healthError})</span>}</p>
          )}
        </div>
        {health === 'healthy' && <StatusBadge tone="success">可用</StatusBadge>}
        {health === 'loading' && <StatusBadge tone="info">检查中</StatusBadge>}
        {health === 'unavailable' && <button type="button" onClick={() => setHealthAttempt((value) => value + 1)}>重试健康检查</button>}
      </div>

      <div className="dashboard-metrics" aria-label="运营指标">
        <Metric label="当前加载报告" value={reportsLoading ? '读取中' : `${reports.length} 份`} />
        <Metric label="已完成闭环" value={reportsLoading ? '读取中' : `${closedReports} 次`} />
        <Metric label="零人工闭环" value={reportsLoading ? '读取中' : `${automaticReports} 次`} />
        <Metric label="已验证动作" value={reportsLoading ? '读取中' : `${verifiedActions} 项`} />
      </div>

      {reportsError && <p className="dashboard-inline-error" role="alert">运营记录暂不可用：{reportsError}</p>}

      <div className="dashboard-command-grid">
        <section className="dashboard-pulse" aria-labelledby="dashboard-pulse-title">
          <header>
            <div><span>最新调查脉冲</span><h3 id="dashboard-pulse-title">{latestReport ? (latestReport.closure.status === 'closed' ? '威胁处置已闭环' : '调查仍在推进') : '等待首个调查信号'}</h3></div>
            <Radar size={28} aria-hidden="true" />
          </header>
          {latestReport ? <>
            <p>{latestReport.closure.observed}</p>
            <ol className="dashboard-loop" aria-label="自动闭环进度">
              <li className={loopState.observed ? 'is-complete' : ''}><span>1</span><strong>观测</strong></li>
              <li className={loopState.decided ? 'is-complete' : ''}><span>2</span><strong>决策</strong></li>
              <li className={loopState.acted ? 'is-complete' : ''}><span>3</span><strong>动作</strong></li>
              <li className={loopState.verified ? 'is-complete' : ''}><span>4</span><strong>验证</strong></li>
            </ol>
            <div className="dashboard-pulse__footer"><code>{latestReport.id}</code><span>{dateTime(latestReport.generated_at)}</span></div>
          </> : <p className="dashboard-muted">完成一次随机演示回放后，这里会呈现真实闭环进度。</p>}
        </section>

        <section className="dashboard-domains" aria-labelledby="dashboard-domains-title">
          <header><div><span>统一证据面</span><h3 id="dashboard-domains-title">跨域证据覆盖</h3></div><Network size={25} aria-hidden="true" /></header>
          {latestReport ? <ul>{latestReport.cross_domain.map((item) => <li key={item.key} className={item.status === 'observed' ? 'is-observed' : ''}>
            <span className="dashboard-domain-dot" aria-hidden="true" /><div><strong>{item.label}</strong><small>{item.status === 'observed' ? `${item.result_count} 项证据` : '本轮未观测'}</small></div>
          </li>)}</ul> : <p className="dashboard-muted">暂无可汇总的跨域证据。</p>}
          {latestReport && <p className="dashboard-domain-total"><strong>{observedDomains.length}</strong> / {latestReport.cross_domain.length} 个证据域已观测</p>}
        </section>
      </div>

      <section className="dashboard-recent" aria-labelledby="dashboard-recent-title">
        <header><div><span>调查档案</span><h3 id="dashboard-recent-title">最近安全运营报告</h3></div><Link to="/operations-report">查看全部 <ArrowUpRight size={15} /></Link></header>
        {reportsLoading && <LoadingState title="正在读取最近调查" />}
        {!reportsLoading && reports.length === 0 && <p className="dashboard-muted">完成安全事件调查后，报告会自动出现在这里。</p>}
        {!reportsLoading && reports.length > 0 && <div className="dashboard-report-list">{reports.slice(0, 4).map((item) => <article key={item.id}>
          <div className="dashboard-report-icon">{item.closure.status === 'closed' ? <CheckCircle2 size={19} /> : <Sparkles size={19} />}</div>
          <div><strong>{item.id}</strong><span>{dateTime(item.generated_at)}</span></div>
          <div className="dashboard-report-outcome"><b>{item.closure.status === 'closed' ? '已闭环' : '分析完成'}</b><small>{item.response_plan?.execution_status === 'verified_completed' ? `${item.response_plan.action_count} 项动作已验证` : '未执行处置'}</small></div>
        </article>)}</div>}
      </section>

      {!context.runId && <section className="dashboard-focus-empty" aria-labelledby="dashboard-focus-title"><div><ShieldCheck size={24} /><div><h3 id="dashboard-focus-title">聚焦某次调查</h3><p>从实时告警进入具体案件，可查看风险、可信证据和验证结果。</p></div></div><Link className="button" to="/alerts">选择实时告警</Link></section>}
      {context.runId && runLoading && <LoadingState title="正在加载运行总览" />}
      {context.runId && runError && <ErrorState title="无法加载运行总览" detail={runError} action={<button type="button" onClick={() => setRunAttempt((value) => value + 1)}>重试加载</button>} />}

      {run && !runLoading && !runError && <>
        <div className="dashboard-metrics dashboard-metrics--run" aria-label="运行指标">
          <Metric label="调查状态" value={statusLabels[run.status] ?? run.status} />
          <Metric label="风险等级" value={risk ? (riskLabels[risk] ?? risk) : '尚未形成'} />
          <Metric label="可信证据" value={`${confirmedEvidence} 条已确认`} />
          <Metric label="处置结果" value={resultLabel(run)} />
        </div>
        <article className="dashboard-case">
          <header>
            <div><StatusBadge tone={run.status === 'closed' ? 'success' : 'info'}>{statusLabels[run.status] ?? run.status}</StatusBadge><h3>{run.assessment?.conclusion ?? '调查尚未形成结论'}</h3></div>
            <StatusBadge tone={verificationLabel(run) === '处置已验证' ? 'success' : 'warning'}>{verificationLabel(run)}</StatusBadge>
          </header>
          <p>事件 <code>{run.incident_tracking_id ?? `INC-${run.incident_id.slice(0, 8).toUpperCase()}`}</code></p>
          <p>运行 <code>{run.run_tracking_id ?? `RUN-${run.run_id.slice(0, 8).toUpperCase()}`}</code></p>
          <Link className="button" to={{ pathname: '/operations-report', search: location.search }}>打开运营报告</Link>
        </article>
      </>}
    </section>
  )
}
