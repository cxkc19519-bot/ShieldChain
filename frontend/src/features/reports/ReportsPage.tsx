import { useCallback, useEffect, useRef, useState } from 'react'

import { useRunContext } from '../../app/RunContext'
import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, LoadingState } from '../../components/ui/States'
import { loadReportBundle } from './api'
import type { ReportBundle, ReportSourceName } from './types'
import './reports.css'

const sourceLabels: Record<ReportSourceName, string> = {
  incident: '事件', investigation: '调查', audit: '审计', agents: '智能体', tools: '可信工具', react: 'ReAct',
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : '报告公开投影加载失败'
}

function timestamp(value: string | null | undefined): string {
  return value ?? '不可用'
}

export function ReportsPage() {
  const context = useRunContext()
  const [bundle, setBundle] = useState<ReportBundle | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const active = useRef<AbortController | null>(null)

  const load = useCallback(async (controller: AbortController) => {
    setLoading(true)
    setError(null)
    try {
      setBundle(await loadReportBundle({ incidentId: context.incidentId, runId: context.runId }, controller.signal))
    } catch (reason) {
      if (!controller.signal.aborted) setError(errorMessage(reason))
    } finally {
      if (active.current === controller) {
        active.current = null
        setLoading(false)
      }
    }
  }, [context.incidentId, context.runId])

  const refresh = useCallback(() => {
    active.current?.abort()
    const controller = new AbortController()
    active.current = controller
    void load(controller)
  }, [load])

  useEffect(() => {
    if (!context.incidentId && !context.runId) {
      active.current?.abort()
      setBundle(null)
      setError(null)
      setLoading(false)
      return
    }
    const controller = new AbortController()
    active.current = controller
    void load(controller)
    return () => controller.abort()
  }, [context.incidentId, context.runId, load])

  const investigation = bundle?.investigation
  const orderedAudit = [...(bundle?.audit?.events ?? [])].sort((left, right) => left.sequence - right.sequence)

  return (
    <section aria-labelledby="reports-title" className="page-card reports-page">
      <PageHeader
        id="reports-title"
        eyebrow="公开投影与可追溯结论"
        title="报告与审计"
        description="组合事件、调查、智能体、可信工具和 ReAct 的只读公开投影；缺失来源不会被推断或补写。"
        actions={<><button disabled={loading || (!context.incidentId && !context.runId)} type="button" onClick={refresh}>刷新报告</button><button className="secondary-button" disabled={!bundle} type="button" onClick={() => window.print()}>打印</button></>}
      />

      {!context.incidentId && !context.runId && <EmptyState title="尚未选择报告范围" detail="在共享案件上下文中选择事件或运行后生成只读报告。" />}
      {loading && !bundle && <LoadingState title="正在生成只读报告" detail="正在并行读取各服务的公开投影。" />}
      {error && <p className="report-error" role="alert">{error}</p>}

      {bundle && <>
        <section aria-labelledby="report-sources-title">
          <div className="report-section-heading"><div><p className="eyebrow">数据完整性</p><h3 id="report-sources-title">公开来源状态</h3></div><span>{Object.values(bundle.sources).filter((source) => source.status === 'available').length}/6 可用</span></div>
          <dl className="report-sources">{(Object.entries(bundle.sources) as [ReportSourceName, ReportBundle['sources'][ReportSourceName]][]).map(([name, source]) => <div key={name} className={`report-source report-source--${source.status}`}><dt>{sourceLabels[name]}</dt><dd><strong>{source.status === 'available' ? '可用' : '不可用'}</strong><small>{source.message}</small></dd></div>)}</dl>
        </section>

        <section aria-labelledby="report-conclusion-title" className="report-conclusion">
          <div className="report-section-heading"><div><p className="eyebrow">结论状态</p><h3 id="report-conclusion-title">调查结论</h3></div>{investigation && <span className="status-badge">{investigation.status}</span>}</div>
          {investigation ? <div className="report-metrics">
            <div><span>研判结论</span><strong>{investigation.assessment?.conclusion ?? '不可用'}</strong></div>
            <div><span>服务端风险</span><strong>{investigation.assessment?.risk_level ?? '不可用'}</strong></div>
            <div><span>阻断验证</span><strong>{investigation.verification ? (investigation.verification.blocked ? '已观测阻断' : '未观测阻断') : '不可用'}</strong></div>
            <div><span>连接验证</span><strong>{investigation.verification ? (investigation.verification.connection_stopped ? '已停止' : '未停止') : '不可用'}</strong></div>
          </div> : <p className="report-unavailable">调查公开投影不可用，无法给出结论状态。</p>}
          {investigation?.assessment && <p>{investigation.assessment.explanation}</p>}
        </section>

        <div className="report-columns">
          <section aria-labelledby="report-incident-title">
            <h3 id="report-incident-title">事件摘要</h3>
            {bundle.incident ? <dl className="report-detail-list"><dt>事件</dt><dd>{bundle.incident.incident.external_id}</dd><dt>威胁</dt><dd>{bundle.incident.incident.threat_label}</dd><dt>终端</dt><dd>{bundle.incident.incident.endpoint}</dd><dt>远端</dt><dd>{bundle.incident.incident.remote_ip}:{bundle.incident.incident.remote_port}</dd></dl> : <p className="report-unavailable">事件公开投影不可用。</p>}
          </section>
          <section aria-labelledby="report-evidence-title">
            <h3 id="report-evidence-title">证据链</h3>
            {investigation?.evidence.length ? <ol className="report-list">{investigation.evidence.map((evidence) => <li key={evidence.id}><strong>{evidence.summary}</strong><span>{evidence.source} · {evidence.integrity_verified ? '完整性已验证' : '完整性未验证'}</span><code>{evidence.integrity_sha256}</code></li>)}</ol> : <p className="report-unavailable">没有可用公开证据。</p>}
          </section>
        </div>

        <div className="report-columns">
          <section aria-labelledby="report-agents-title"><h3 id="report-agents-title">智能体协作</h3>{bundle.collaboration ? <><p>{bundle.collaboration.shared_summary}</p><ul className="report-list">{bundle.collaboration.confirmed_facts.map((fact) => <li key={fact}>{fact}</li>)}</ul><p><small>阶段 {bundle.collaboration.phase} · 修订 {bundle.collaboration.revision}</small></p></> : <p className="report-unavailable">智能体公开轨迹不可用。</p>}</section>
          <section aria-labelledby="report-react-title"><h3 id="report-react-title">ReAct 决策</h3>{bundle.react ? <><p><span className="status-badge">{bundle.react.status}</span> · 修订 {bundle.react.revision}</p>{bundle.react.decisions.length ? <ol className="report-list">{bundle.react.decisions.map((decision) => <li key={decision.id}><strong>{decision.decision}</strong><span>{decision.reason_code} · {decision.decided_at}</span></li>)}</ol> : <p>没有公开决策。</p>}</> : <p className="report-unavailable">ReAct 公开轨迹不可用。</p>}</section>
        </div>

        <section aria-labelledby="report-tools-title"><h3 id="report-tools-title">可信工具处置</h3>{bundle.tools?.calls.length ? <div className="report-tool-grid">{bundle.tools.calls.map((call) => <article key={call.id}><div><span className="status-badge">{call.status}</span><span>风险 {call.risk ?? '待评估'}</span></div><h4>{call.tool_name} · <code>{call.target}</code></h4><p>策略 {call.policy_outcome ?? '待定'} · 审批 {call.approval_outcome ?? '待定'} · 验证 {call.verification_outcome ?? '待验证'}</p></article>)}</div> : <p className="report-unavailable">没有可用可信工具轨迹。</p>}</section>

        <section aria-labelledby="report-audit-title">
          <div className="report-section-heading"><div><p className="eyebrow">有序且只读</p><h3 id="report-audit-title">审计时间线</h3></div><span>{orderedAudit.length} 个事件</span></div>
          {orderedAudit.length ? <ol className="report-audit">{orderedAudit.map((event) => <li data-testid="audit-event" key={event.id}><span>{event.sequence}</span><div><strong>{event.event_type}</strong><p><time dateTime={event.occurred_at}>{event.occurred_at}</time></p><small>请求 {event.request_id}</small></div></li>)}</ol> : <p className="report-unavailable">审计公开投影不可用或没有事件。</p>}
        </section>

        <footer className="report-footer">报告范围：事件 {context.incidentId ?? '不可用'} · 运行 {context.runId ?? '不可用'} · 调查更新时间 {timestamp(investigation?.updated_at)}</footer>
      </>}
    </section>
  )
}
