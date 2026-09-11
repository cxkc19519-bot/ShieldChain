import { useCallback, useEffect, useState } from 'react'
import { BadgeCheck, Bot, BrainCircuit, CheckCircle2, ChevronDown, ChevronUp, Play, Radar, RefreshCcw, RotateCcw, ShieldAlert, ShieldCheck, Trash2, Wrench, X } from 'lucide-react'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { deleteFinding, listFindings, loadMetrics, mutateFinding, runVulnerabilityDemo, type VulnerabilityFinding, type VulnerabilityMetrics } from './api'
import './vulnerabilities.css'

const statusLabel: Record<VulnerabilityFinding['status'], string> = {
  new: '待智能体研判', triaged: '待人工决策', remediation_approved: '修复已批准',
  remediation_in_progress: '修复实施中', verification_pending: '等待复测',
  closed: '已闭环', accepted_risk: '限期接受风险',
}

const eventLabel: Record<string, string> = {
  finding_ingested: '扫描发现入库', agent_triage_completed: '智能体完成研判',
  remediation_approved: '人工批准修复', risk_accepted: '人工接受风险',
  finding_not_affected: '确认不受影响', remediation_started: '登记修复变更',
  remediation_completed: '修复实施完成', verification_passed: '复测通过', verification_failed: '复测失败并退回研判',
  demo_policy_authorized: '智能体决策与安全边界校验', demo_remediation_started: '模拟修复工具已调用',
  demo_remediation_succeeded: '模拟修复执行成功', demo_verification_passed: '模拟扫描器复测通过',
  demo_verification_failed: '模拟扫描器复测失败', demo_replan_authorized: '智能体根据反馈重新规划',
  demo_not_affected_verified: '证据核验后排除误报',
}

const demoScenarioLabel: Record<string, string> = {
  component_upgrade: '组件升级', configuration_hardening: '配置加固',
  container_image_replacement: '容器镜像替换', service_exposure_reduction: '服务暴露收敛',
  retest_failure_replan: '复测失败后重新规划', compensating_control: '补偿控制',
  scanner_false_positive: '扫描误报排除',
}

const actorLabel: Record<string, string> = { scanner: '扫描器', agent: '智能体', human: '人工操作员', system: '策略与工具服务' }
const versionlessScenarios = new Set(['configuration_hardening', 'service_exposure_reduction'])

function displayVersion(item: VulnerabilityFinding, value: string | null): string {
  if (value) return value
  const ingestion = item.events.find((event) => event.event_type === 'finding_ingested')
  const evidence = ingestion?.details.evidence
  const scenario = evidence && typeof evidence === 'object' && !Array.isArray(evidence)
    ? (evidence as Record<string, unknown>).scenario
    : null
  return typeof scenario === 'string' && versionlessScenarios.has(scenario) ? '不适用' : '待核对'
}

function concise(value: string, maximum = 105): string {
  const normalized = value.replace(/\s+/g, ' ').trim()
  return normalized.length > maximum ? `${normalized.slice(0, maximum)}…` : normalized
}

function formatChinaDateTime(value: string): string {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: 'numeric', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3,
    hour12: false,
  }).format(new Date(value))
}

function workflowIcon(eventType: string) {
  if (eventType === 'finding_ingested') return Radar
  if (eventType === 'agent_triage_completed') return Bot
  if (eventType.includes('replan')) return RotateCcw
  if (eventType.includes('authorized') || eventType === 'remediation_approved' || eventType === 'risk_accepted') return ShieldCheck
  if (eventType.includes('remediation') || eventType.includes('implementation') || eventType === 'remediation_started') return Wrench
  if (eventType.includes('verification') || eventType === 'finding_not_affected') return BadgeCheck
  return CheckCircle2
}

function workflowNodes(item: VulnerabilityFinding) {
  return item.events.map((event) => {
    const facts: string[] = []
    if (event.details.priority) facts.push(String(event.details.priority))
    if (event.details.model) facts.push(String(event.details.model))
    if (event.details.agent_model) facts.push(String(event.details.agent_model))
    if (event.details.tool_name) facts.push(String(event.details.tool_name))
    if (typeof event.details.attempt === 'number') facts.push(`第 ${event.details.attempt} 次`)
    if (typeof event.details.duration_ms === 'number') facts.push(`${event.details.duration_ms} ms`)
    return {
      id: event.id,
      label: eventLabel[event.event_type] ?? event.event_type,
      detail: concise(event.summary, 150),
      facts,
      meta: `${actorLabel[event.actor_type] ?? event.actor_type} · ${formatChinaDateTime(event.created_at)}`,
      className: event.event_type.includes('failed')
        ? 'is-failed'
        : event.event_type.includes('replan')
          ? 'is-replan'
          : '',
      icon: workflowIcon(event.event_type),
    }
  })
}

export function VulnerabilitiesPage() {
  const [items, setItems] = useState<VulnerabilityFinding[]>([])
  const [metrics, setMetrics] = useState<VulnerabilityMetrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [note, setNote] = useState<Record<string, string>>({})
  const [ticket, setTicket] = useState<Record<string, string>>({})
  const [attempt, setAttempt] = useState(0)
  const [demoMessage, setDemoMessage] = useState<string | null>(null)
  const [workflowFinding, setWorkflowFinding] = useState<VulnerabilityFinding | null>(null)
  const [expandedFindingIds, setExpandedFindingIds] = useState<Set<string>>(() => new Set())

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setLoading(true); setError(null)
    try {
      const [nextItems, nextMetrics] = await Promise.all([listFindings(signal), loadMetrics(signal)])
      setItems(nextItems); setMetrics(nextMetrics)
    } catch (reason) { if (!signal?.aborted) setError(reason instanceof Error ? reason.message : '无法加载漏洞闭环') }
    finally { if (!signal?.aborted) setLoading(false) }
  }, [])

  useEffect(() => {
    const controller = new AbortController(); void refresh(controller.signal)
    return () => controller.abort()
  }, [attempt, refresh])

  const run = async (item: VulnerabilityFinding, action: string, payload: Record<string, unknown>) => {
    setBusy(item.id); setError(null)
    try {
      await mutateFinding(item.id, action, payload)
      setAttempt((value) => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '漏洞闭环操作失败') }
    finally { setBusy(null) }
  }

  const runDemo = async () => {
    setBusy('demo'); setError(null); setDemoMessage(null)
    try {
      const result = await runVulnerabilityDemo()
      const succeeded = result.tool_calls.filter((item) => item.status === 'succeeded').length
      const failed = result.tool_calls.length - succeeded
      setDemoMessage(`${result.finding.cve_id} 已完成零人工漏洞闭环（${demoScenarioLabel[result.scenario] ?? result.scenario}）：共 ${result.tool_calls.length} 次模拟工具调用，成功 ${succeeded} 次${failed ? `、反馈失败 ${failed} 次并已重新规划` : ''}，总耗时 ${result.total_duration_ms} ms。`)
      setAttempt((value) => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '漏洞演示闭环失败') }
    finally { setBusy(null) }
  }

  const remove = async (item: VulnerabilityFinding) => {
    if (!window.confirm(`删除 ${item.cve_id} 在 ${item.asset_name} 上的漏洞记录及全部闭环审计事件？此操作无法恢复。`)) return
    setBusy(item.id); setError(null)
    try {
      await deleteFinding(item.id)
      if (workflowFinding?.id === item.id) setWorkflowFinding(null)
      setExpandedFindingIds((current) => {
        const next = new Set(current)
        next.delete(item.id)
        return next
      })
      setItems((current) => current.filter((candidate) => candidate.id !== item.id))
      setAttempt((value) => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '删除漏洞记录失败') }
    finally { setBusy(null) }
  }

  const rationale = (item: VulnerabilityFinding) => note[item.id] ?? ''
  const changeTicket = (item: VulnerabilityFinding) => ticket[item.id] ?? ''
  const disabled = (item: VulnerabilityFinding, needsTicket = false) => busy !== null || rationale(item).trim().length < 10 || (needsTicket && changeTicket(item).trim().length < 3)
  const toggleDetails = (findingId: string) => setExpandedFindingIds((current) => {
    const next = new Set(current)
    if (next.has(findingId)) next.delete(findingId)
    else next.add(findingId)
    return next
  })

  return <section className="page-card vulnerabilities-page" aria-labelledby="vulnerabilities-title">
    <PageHeader id="vulnerabilities-title" title="漏洞排查与闭环" centered
      actions={<><button type="button" disabled={busy !== null} onClick={() => void runDemo()}><Play size={16} /> {busy === 'demo' ? '自动闭环中…' : '导入演示漏洞'}</button><button type="button" disabled={busy !== null} onClick={() => setAttempt((value) => value + 1)}><RefreshCcw size={16} /> 刷新</button></>} />
    {demoMessage && <p className="vulnerability-demo-message" role="status">{demoMessage}</p>}
    {metrics && <div className="vulnerability-metrics" aria-label="漏洞闭环指标">
      <div><span>全部发现</span><strong>{metrics.total}</strong></div><div><span>未闭环</span><strong>{metrics.open}</strong></div>
      <div><span>严重未闭环</span><strong>{metrics.critical_open}</strong></div><div><span>待人工批准</span><strong>{metrics.awaiting_approval}</strong></div>
      <div><span>等待复测</span><strong>{metrics.verification_pending}</strong></div><div><span>已闭环</span><strong>{metrics.closed}</strong></div>
    </div>}
    {loading && <LoadingState title="正在加载漏洞台账" detail="读取扫描器发现与不可覆盖的闭环审计记录。" />}
    {error && !loading && <ErrorState title="漏洞闭环暂不可用" detail={error} action={<button type="button" onClick={() => setAttempt((value) => value + 1)}>重试</button>} />}
    {!loading && !error && items.length === 0 && <EmptyState title="暂无扫描器漏洞发现" detail="配置扫描器令牌并通过受控 API 导入结果后，发现会显示在这里；系统不会把告警中的 CVE 字样自动当成已确认漏洞。" />}
    {!loading && items.length > 0 && <div className="vulnerability-list">
      {items.map((item) => {
        const expanded = expandedFindingIds.has(item.id)
        const detailsId = `vulnerability-details-${item.id}`
        return <article key={item.id} className={`vulnerability-card severity-${item.severity}`}>
        <header><div><p className="eyebrow">{item.scanner} · {item.asset_name}</p><h3>{item.cve_id}</h3></div><div className="vulnerability-card__header-actions"><span className="vulnerability-status">{statusLabel[item.status]}</span><button className="secondary-button vulnerability-expand-button" type="button" aria-expanded={expanded} aria-controls={detailsId} onClick={() => toggleDetails(item.id)}>{expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}{expanded ? '收起详情' : '展开详情'}</button></div></header>
        <dl><div><dt>严重性</dt><dd>{item.severity.toUpperCase()}{item.cvss_score === null ? '' : ` · CVSS ${item.cvss_score}`}</dd></div>
          <div><dt>组件</dt><dd>{item.package_name ?? '未提供'}</dd></div><div><dt>当前版本</dt><dd>{displayVersion(item, item.installed_version)}</dd></div><div><dt>修复版本</dt><dd>{displayVersion(item, item.fixed_version)}</dd></div></dl>
        {expanded && <div id={detailsId} className="vulnerability-card__details">
        {item.latest_triage && <section className="agent-triage"><strong>漏洞研判智能体 · {String(item.latest_triage.details.priority ?? '待分级')}</strong>
          <p>{item.latest_triage.summary}</p><small>{item.latest_triage.details.agent_status === 'completed' ? `模型：${String(item.latest_triage.details.model)}` : '模型不可用时采用保守降级，必须人工核实。'}</small>
          <div><b>影响判断</b><p>{String(item.latest_triage.details.affected_assessment ?? '')}</p><b>修复建议</b><p>{String(item.latest_triage.details.remediation ?? '')}</p><b>复测标准</b><p>{String(item.latest_triage.details.verification ?? '')}</p></div>
        </section>}
        {['triaged', 'remediation_approved', 'remediation_in_progress', 'verification_pending'].includes(item.status) && <div className="vulnerability-action-form">
          {(item.status === 'remediation_approved' || item.status === 'remediation_in_progress') && <input value={changeTicket(item)} onChange={(event) => setTicket((old) => ({ ...old, [item.id]: event.target.value }))} placeholder="变更单号，例如 CHG-2026-001" />}
          <textarea value={rationale(item)} onChange={(event) => setNote((old) => ({ ...old, [item.id]: event.target.value }))} placeholder="至少 10 个字符，记录人工依据、实施情况或复测证据。" maxLength={1000} />
        </div>}
        <div className="vulnerability-actions">
          <button className="secondary-button" type="button" onClick={() => setWorkflowFinding(item)}><BrainCircuit size={16} /> 查看智能体工作链</button>
          {item.status === 'new' && <button disabled={busy !== null} onClick={() => void run(item, 'triage', { business_context: null })}><ShieldAlert size={16} /> {busy === item.id ? '研判中…' : '启动智能体研判'}</button>}
          {item.status === 'triaged' && <><button disabled={disabled(item)} onClick={() => void run(item, 'decision', { outcome: 'approve_remediation', reason_code: 'confirmed_exposure', rationale: rationale(item), risk_expires_at: null })}><CheckCircle2 size={16} /> 批准修复</button>
            <button className="secondary-button" disabled={disabled(item)} onClick={() => void run(item, 'decision', { outcome: 'mark_not_affected', reason_code: 'version_not_affected', rationale: rationale(item), risk_expires_at: null })}>确认不受影响</button>
            <button className="secondary-button" disabled={disabled(item)} onClick={() => void run(item, 'decision', { outcome: 'accept_risk', reason_code: 'business_exception', rationale: rationale(item), risk_expires_at: new Date(Date.now() + 30 * 86400000).toISOString() })}>接受风险 30 天</button></>}
          {item.status === 'remediation_approved' && <button disabled={disabled(item, true)} onClick={() => void run(item, 'changes', { change_ticket: changeTicket(item), implementer: '人工操作员', planned_at: new Date().toISOString(), plan_summary: rationale(item) })}><Wrench size={16} /> 登记开始实施</button>}
          {item.status === 'remediation_in_progress' && <button disabled={disabled(item, true)} onClick={() => void run(item, 'implementation', { change_ticket: changeTicket(item), implementation_summary: rationale(item), evidence_references: [`change:${changeTicket(item)}`] })}>记录实施完成</button>}
          {item.status === 'verification_pending' && <><button disabled={disabled(item)} onClick={() => void run(item, 'verification', { result: 'passed', scanner: item.scanner, observed_version: item.fixed_version, evidence_references: [`retest:${item.external_id}`], summary: rationale(item) })}>复测通过并关闭</button>
            <button className="secondary-button" disabled={disabled(item)} onClick={() => void run(item, 'verification', { result: 'failed', scanner: item.scanner, observed_version: item.installed_version, evidence_references: [`retest:${item.external_id}`], summary: rationale(item) })}>复测失败，退回研判</button></>}
          <button className="danger-button vulnerability-delete-button" type="button" disabled={busy !== null} onClick={() => void remove(item)}><Trash2 size={16} />{busy === item.id ? '正在删除…' : '删除记录'}</button>
        </div>
        {item.events.some((event) => ['succeeded', 'failed'].includes(String(event.details.tool_status))) && <section className="vulnerability-tool-receipts"><strong>自动闭环工具回执</strong>{item.events.filter((event) => ['succeeded', 'failed'].includes(String(event.details.tool_status))).map((event) => <div key={`tool-${event.id}`}><code>{String(event.details.tool_name)}</code><span className={event.details.tool_status === 'failed' ? 'failed' : ''}>{String(event.details.tool_status)} · {String(event.details.duration_ms ?? '—')} ms</span><p>{event.summary}</p></div>)}</section>}
        <details><summary>审计时间线（{item.events.length}）</summary><ol className="vulnerability-timeline">{item.events.map((event) => <li key={event.id}><strong>{eventLabel[event.event_type] ?? event.event_type}</strong><span>{formatChinaDateTime(event.created_at)}</span><p>{event.summary}</p></li>)}</ol></details>
        </div>}
      </article>
      })}
    </div>}
    {workflowFinding && <div className="vulnerability-workflow-overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) setWorkflowFinding(null) }}>
      <section className="vulnerability-workflow-dialog" role="dialog" aria-modal="true" aria-labelledby="vulnerability-workflow-title">
        <header><div><p className="eyebrow">漏洞智能体审计视图</p><h2 id="vulnerability-workflow-title">动态漏洞处置工作链</h2><p>{workflowFinding.cve_id} · {workflowFinding.asset_name}</p></div>
          <button className="icon-button" type="button" aria-label="关闭智能体工作链" onClick={() => setWorkflowFinding(null)}><X size={22} /></button></header>
        {workflowFinding.events.length > 0
          ? <ol className="vulnerability-workflow-chain" aria-label="漏洞智能体工作链">{workflowNodes(workflowFinding).map((node, index) => <li key={node.id} className={node.className}>
            <span className="vulnerability-workflow-chain__index">{String(index + 1).padStart(2, '0')}</span><node.icon size={20} /><strong>{node.label}</strong><p>{node.detail}</p>
            {node.facts.length > 0 && <small className="vulnerability-workflow-chain__facts">{node.facts.join(' · ')}</small>}<small>{node.meta}</small>
          </li>)}</ol>
          : <p className="vulnerability-workflow-empty">尚无已保存的工作事件。</p>}
        {Array.isArray(workflowFinding.latest_triage?.details.evidence_gaps) && workflowFinding.latest_triage.details.evidence_gaps.length > 0 && <section className="vulnerability-workflow-gaps"><h3>研判时仍缺少的证据</h3><ul>{workflowFinding.latest_triage.details.evidence_gaps.map((gap, index) => <li key={`${index}-${String(gap)}`}>{String(gap)}</li>)}</ul></section>}
        <section className="vulnerability-workflow-audit"><h3>完整工作回执</h3><ol>{workflowFinding.events.map((event) => <li key={event.id}><div><strong>{eventLabel[event.event_type] ?? event.event_type}</strong><span>{actorLabel[event.actor_type] ?? event.actor_type} · {formatChinaDateTime(event.created_at)}</span></div><p>{event.summary}</p>
          <small>{event.from_status ? `${statusLabel[event.from_status]} → ` : ''}{statusLabel[event.to_status]} · 原因码 {event.reason_code}{typeof event.details.duration_ms === 'number' ? ` · ${event.details.duration_ms} ms` : ''}</small></li>)}</ol></section>
      </section>
    </div>}
  </section>
}
