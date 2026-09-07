import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'

import { getLiveness } from '../../api/client'
import { useRunContext } from '../../app/RunContext'
import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { StatusBadge } from '../../components/ui/StatusBadge'
import { getInvestigation } from '../investigation/api'
import type { InvestigationResponse } from '../investigation/types'
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

function Metric({ label, value }: { label: string; value: string }) {
  return <article className="dashboard-metric"><span>{label}</span><strong>{value}</strong></article>
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
        if (!controller.signal.aborted) setRunError(failure instanceof Error ? failure.message : '无法加载调查总览')
      },
    ).finally(() => { if (!controller.signal.aborted) setRunLoading(false) })
    return () => controller.abort()
  }, [context.runId, runAttempt])

  const confirmedEvidence = run?.evidence.filter((item) => item.confirmed && item.integrity_verified).length ?? 0
  const risk = run?.assessment?.risk_level

  return (
    <section aria-labelledby="dashboard-title" className="page-card dashboard-page">
      <PageHeader
        id="dashboard-title"
        eyebrow="Security posture"
        title="运营总览"
        description="基于当前离线仿真运行的公开调查投影，汇总风险、证据、处置与验证状态。"
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

      {!context.runId && <EmptyState title="尚未选择调查运行" detail="前往事件调查启动仿真，或在左侧输入已有运行 ID。" />}
      {context.runId && runLoading && <LoadingState title="正在加载运行总览" />}
      {context.runId && runError && <ErrorState title="无法加载运行总览" detail={runError} action={<button type="button" onClick={() => setRunAttempt((value) => value + 1)}>重试加载</button>} />}

      {run && !runLoading && !runError && <>
        <div className="dashboard-metrics" aria-label="运行指标">
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
