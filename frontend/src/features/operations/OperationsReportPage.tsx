import { useCallback, useEffect, useState } from 'react'
import { Activity, BadgeCheck, BrainCircuit, CheckCircle2, ExternalLink, FileDown, Gavel, MonitorCog, RefreshCcw, Shield, ShieldCheck, Trash2, UserRound, X } from 'lucide-react'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { deleteOperationsReport, listOperationsReports, type OperationsReport } from './api'
import './operations.css'

function dateTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

function reportStatus(report: OperationsReport): string {
  if (report.closure.status === 'closed') return '已闭环'
  if (report.closure.status === 'verification_pending') return '等待验证'
  if (report.closure.status === 'awaiting_approval') return '异常待接管'
  return '分析完成'
}

function shortened(value: string, maximum = 92): string {
  const normalized = value.replace(/^概括总结：\s*/, '').replace(/\s+/g, ' ').trim()
  return normalized.length > maximum ? `${normalized.slice(0, maximum)}…` : normalized
}

function match(value: string, pattern: RegExp): string | null {
  return value.match(pattern)?.[1]?.trim() ?? null
}

function attackChain(report: OperationsReport) {
  const narrative = [report.closure.decision, ...report.reasoning_trace.map((step) => step.detail)].join(' ')
  const alertEvidence = report.tool_calls
    .find((item) => item.name === 'security.alerts.list')
    ?.items.join(' ') ?? ''
  const structuredEvidence = `${alertEvidence} ${narrative}`
  const observedDomain = (...tokens: string[]) => report.cross_domain.find((item) => {
    const identity = `${item.key} ${item.label}`.toLowerCase()
    return item.status === 'observed' && item.result_count > 0 && tokens.some((token) => identity.includes(token))
  })
  const networkDomain = observedDomain('network', '网络', '流量', '告警')
  const endpointDomain = observedDomain('endpoint', '终端', '端点')
  const identityDomain = observedDomain('identity', '身份', '账号', '认证')
  const vulnerabilityDomain = observedDomain('vulnerability', '漏洞', '攻击面')
  const source = match(structuredEvidence, /(?:网络\s*|源(?:地址|IP)?\s*)([0-9a-f:.]+)\s*(?:→|向)/i)
  const target = match(structuredEvidence, /(?:→|向目标|攻击目标)\s*([0-9a-f:.]+(?::\d+)?)/i)
  const rule = match(structuredEvidence, /(?:关联)?规则\s*([a-z][a-z0-9_-]*:\d+)/i)
  const alertSignature = match(alertEvidence, /｜\s*(?:NTA\s*隔离回放[：:]\s*)?([^｜]+?)\s*｜\s*网络/i)
  const attackFeature = alertSignature
    ?? match(narrative, /表现为\s*([^，。]{4,100})/)
    ?? match(narrative, /检测到(?:一次)?\s*([^，。]{4,100})/)
  const process = match(narrative, /(?:名为\s*)?([a-z0-9_.-]+)\s*(?:的)?端点进程/i)
    ?? match(narrative, /端点(?:映射|进程上下文)?[^，。]{0,20}?([a-z0-9_.-]+)(?:执行|与)/i)
  const account = match(narrative, /(?:服务账号|身份线索(?:为)?|账号)\s*([a-z0-9_.-]+)/i)
  const endpoint = report.response_audit?.actions.find((item) => item.target_type === 'endpoint')?.target
  const actionNames: Record<string, string> = { block_ip: '封禁 IP', isolate_endpoint: '隔离端点', quarantine_file: '隔离文件', disable_account: '停用账号' }
  const behavior = /内鬼/.test(narrative)
    ? `${attackFeature ? `${shortened(attackFeature, 62)}；` : ''}身份与行为证据指向疑似内鬼活动`
    : /隔离回放|演示环境/.test(narrative)
      ? `${attackFeature ? `${shortened(attackFeature, 62)}；` : ''}判定为隔离回放攻击行为`
      : shortened(report.closure.decision)
  const traffic = source && target
    ? `${source} → ${target}${rule ? ` · ${rule}` : ''}${alertSignature ? ` · ${shortened(alertSignature, 42)}` : ''}`
    : `${shortened(networkDomain?.summary ?? report.closure.observed)}${rule ? ` · ${rule}` : ''}`
  const demoMappedContext = /演示映射|demo_scenario_mapping|不是生产身份|非生产身份/.test(structuredEvidence)
  const nodes: Array<{ key: string; label: string; detail: string; icon: typeof Activity; state: 'complete' | 'pending' | 'failed' }> = []

  if (networkDomain || alertEvidence || (source && target)) {
    nodes.push({ key: 'network', label: '网络告警', detail: traffic, icon: Activity, state: 'complete' })
  }
  if (endpointDomain && !demoMappedContext) {
    nodes.push({ key: 'endpoint', label: '终端关联', detail: process ? `${process}${endpoint ? ` · 端点 ${endpoint}` : ''}` : shortened(endpointDomain.summary), icon: MonitorCog, state: 'complete' })
  }
  if (identityDomain && !demoMappedContext) {
    nodes.push({ key: 'identity', label: '身份关联', detail: account ? `${account} · 已取得身份域证据` : shortened(identityDomain.summary), icon: UserRound, state: 'complete' })
  }
  if (vulnerabilityDomain) {
    nodes.push({ key: 'vulnerability', label: '攻击面线索', detail: shortened(vulnerabilityDomain.summary), icon: ShieldCheck, state: 'complete' })
  }
  nodes.push({ key: 'decision', label: '研判结论', detail: behavior, icon: Gavel, state: report.closure.status === 'analysis_complete' ? 'pending' : 'complete' })

  const auditedActions = report.response_audit?.actions ?? []
  for (const action of auditedActions) {
    const failed = action.execution_status === 'failed' || action.attempt_outcomes.some((outcome) => /failed|失败/i.test(outcome))
    const completed = action.execution_status === 'succeeded' || action.verification_outcome === 'verified'
    nodes.push({
      key: `action-${action.action_id}`,
      label: actionNames[action.tool_name] ?? action.tool_name,
      detail: `${action.target_type} ${action.target} · ${failed ? '执行失败' : completed ? '已取得执行回执' : action.execution_status}`,
      icon: Shield,
      state: failed ? 'failed' : completed ? 'complete' : 'pending',
    })
  }
  if (auditedActions.length === 0 && report.response_plan && report.response_plan.action_count > 0) {
    nodes.push({ key: 'proposal', label: '响应建议', detail: shortened(report.response_plan.public_summary), icon: Shield, state: 'pending' })
  }

  const replans = report.response_audit?.replans.filter((item) => item.revision > 0 || /replan|重新规划|失败反馈/i.test(`${item.event_type} ${item.summary}`)) ?? []
  if (replans.length > 0) {
    nodes.push({ key: 'replan', label: '反馈重规划', detail: shortened(replans.at(-1)?.summary ?? `已生成 ${replans.length} 次修订。`), icon: RefreshCcw, state: 'complete' })
  }
  if (auditedActions.length > 0 || report.closure.status === 'verification_pending') {
    const verified = auditedActions.filter((action) => action.verification_outcome === 'verified').length
    const verificationFailed = auditedActions.some((action) => /failed|失败/i.test(action.verification_outcome ?? ''))
    nodes.push({
      key: 'verification',
      label: verificationFailed ? '验证失败' : report.closure.status === 'verification_pending' ? '等待验证' : '结果验证',
      detail: auditedActions.length ? `${verified}/${auditedActions.length} 项动作验证通过；${shortened(report.closure.verification, 72)}` : shortened(report.closure.verification),
      icon: BadgeCheck,
      state: verificationFailed ? 'failed' : report.closure.status === 'verification_pending' ? 'pending' : 'complete',
    })
  } else if (report.closure.status === 'awaiting_approval') {
    nodes.push({ key: 'takeover', label: '等待人工接管', detail: shortened(report.closure.feedback), icon: UserRound, state: 'pending' })
  }
  return nodes
}

function AttackChainView({ report }: { report: OperationsReport }) {
  const nodes = attackChain(report)
  return <ol className="operations-attack-chain" aria-label="动态攻击调查链" style={{ gridTemplateColumns: `repeat(${nodes.length}, minmax(165px, 1fr))`, minWidth: `${Math.max(760, nodes.length * 190)}px` }}>
    {nodes.map((node, index) => <li key={node.key} className={`is-${node.state}`}><span className="operations-attack-chain__index">{String(index + 1).padStart(2, '0')}</span><node.icon size={20} /><strong>{node.label}</strong><p>{node.detail}</p></li>)}
  </ol>
}

export function OperationsReportPage() {
  const [reports, setReports] = useState<OperationsReport[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [reasoningReport, setReasoningReport] = useState<OperationsReport | null>(null)

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setError(null)
    try {
      const next = await listOperationsReports(signal)
      if (!signal?.aborted) setReports(next)
    } catch (reason) {
      if (!signal?.aborted) setError(reason instanceof Error ? reason.message : '加载运营报告失败')
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void refresh(controller.signal)
    return () => controller.abort()
  }, [refresh])

  useEffect(() => {
    if (!reasoningReport) return
    const close = (event: KeyboardEvent) => { if (event.key === 'Escape') setReasoningReport(null) }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [reasoningReport])

  const remove = async (report: OperationsReport) => {
    if (!window.confirm(`确定删除“${report.id}”吗？服务器上的 HTML、Markdown 和元数据文件也会被删除，此操作无法撤销。`)) return
    setDeletingId(report.id)
    setError(null)
    try {
      await deleteOperationsReport(report.id)
      setReports((items) => items.filter((item) => item.id !== report.id))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '删除安全运营报告失败')
    } finally {
      setDeletingId(null)
    }
  }

  return <section aria-labelledby="operations-title" className="page-card operations-page operations-index-page">
    <PageHeader
      id="operations-title"
      title="安全运营报告"
      centered
      actions={<button type="button" onClick={() => void refresh()} disabled={loading}><RefreshCcw size={16} />刷新报告</button>}
    />

    {loading && reports.length === 0 && <LoadingState title="正在读取安全运营报告" />}
    {error && <ErrorState title="无法加载安全运营报告" detail={error} action={<button type="button" onClick={() => void refresh()}>重试</button>} />}
    {!loading && !error && reports.length === 0 && <EmptyState title="尚无安全运营报告" detail="智能体完成安全事件调查后，报告会自动出现在这里。" />}

    {reports.length > 0 && <div className="operations-report-grid" role="list">
      {reports.map((report) => {
        const observedDomains = report.cross_domain.filter((item) => item.status === 'observed').length
        const zeroTouch = report.response_audit?.human_interventions === 0 || (report.closure.status === 'closed' && !report.closure.human_approval_required)
        return <article className="operations-report-card" key={report.id} role="listitem">
          <header>
            <div className="operations-report-card__icon">{zeroTouch ? <ShieldCheck size={23} /> : <CheckCircle2 size={23} />}</div>
            <div><h3>{report.id}</h3><time dateTime={report.generated_at}>{dateTime(report.generated_at)}</time></div>
            <span className={report.closure.status === 'closed' ? 'is-closed' : ''}>{reportStatus(report)}</span>
          </header>
          <div className="operations-report-card__metrics">
            <div><span>处置模式</span><strong>{zeroTouch ? '零人工闭环' : '受控调查'}</strong></div>
            <div><span>处置动作</span><strong>{report.response_plan?.action_count ?? 0} 项</strong></div>
            <div><span>证据覆盖</span><strong>{observedDomains}/{report.cross_domain.length} 域</strong></div>
            <div><span>人工干预</span><strong>{report.response_audit ? `${report.response_audit.human_interventions} 次` : report.closure.human_approval_required ? '需要' : '0 次'}</strong></div>
          </div>
          <p>{report.closure.observed}</p>
          <footer>
            <a className="button" href={`/api/v1/operations/reports/${encodeURIComponent(report.id)}/view`} target="_blank" rel="noreferrer"><ExternalLink size={16} />打开 HTML 报告</a>
            <a href={`/api/v1/operations/reports/${encodeURIComponent(report.id)}/view?download=true`}><FileDown size={16} />下载 HTML</a>
            <a href={`/api/v1/operations/reports/${encodeURIComponent(report.id)}/download?format=markdown`}><FileDown size={16} />下载 Markdown</a>
            <button className="reasoning-button" type="button" onClick={() => setReasoningReport(report)}><BrainCircuit size={16} />查看思维链</button>
            <button className="danger-button" disabled={deletingId === report.id} type="button" onClick={() => void remove(report)}><Trash2 size={16} />{deletingId === report.id ? '正在删除…' : '删除报告'}</button>
          </footer>
        </article>
      })}
    </div>}

    {reasoningReport && <div className="operations-reasoning-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setReasoningReport(null) }}>
      <section className="operations-reasoning-dialog" role="dialog" aria-modal="true" aria-labelledby="reasoning-dialog-title">
        <header><div><span>攻击调查时间线</span><h2 id="reasoning-dialog-title">结构化调查思维链</h2><p>{reasoningReport.id}</p></div><button type="button" aria-label="关闭思维链" onClick={() => setReasoningReport(null)}><X size={20} /></button></header>
        <p className="operations-reasoning-dialog__notice">展示智能体可公开审计的事实、证据关联、协作结论、决策、动作和验证，不包含模型隐藏思维文本。</p>
        <div className="operations-attack-chain-wrap"><AttackChainView report={reasoningReport} /></div>
        {reasoningReport.reasoning_trace.length === 0 ? <EmptyState title="该报告没有结构化调查链" detail="早期报告可能只保存了最终结论，请打开 HTML 报告查看已有证据。" /> : <ol className="operations-reasoning__timeline">
          {reasoningReport.reasoning_trace.map((step) => <li key={`${step.sequence}-${step.phase}`} className={`is-${step.status}`}>
            <span className="operations-reasoning__marker">{step.sequence}</span>
            <div className="operations-reasoning__content"><div className="operations-reasoning__title"><strong>{step.title}</strong><span>{Math.round(step.confidence * 100)}% · {step.status === 'completed' ? '已完成' : step.status === 'pending' ? '待确认' : '已阻断'}</span></div><p>{step.detail}</p><small>证据域：{step.domains.length ? step.domains.join('、') : '未标注'}</small>{step.evidence.length > 0 && <details><summary>查看证据引用（{step.evidence.length}）</summary><ul>{step.evidence.map((item) => <li key={item}><code>{item}</code></li>)}</ul></details>}</div>
          </li>)}
        </ol>}
      </section>
    </div>}
  </section>
}
