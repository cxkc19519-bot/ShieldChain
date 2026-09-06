import { useCallback, useEffect, useState } from 'react'
import { CheckCircle2, RefreshCcw, ShieldAlert, Wrench } from 'lucide-react'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { listFindings, loadMetrics, mutateFinding, type VulnerabilityFinding, type VulnerabilityMetrics } from './api'
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

  const rationale = (item: VulnerabilityFinding) => note[item.id] ?? ''
  const changeTicket = (item: VulnerabilityFinding) => ticket[item.id] ?? ''
  const disabled = (item: VulnerabilityFinding, needsTicket = false) => busy !== null || rationale(item).trim().length < 10 || (needsTicket && changeTicket(item).trim().length < 3)

  return <section className="page-card vulnerabilities-page" aria-labelledby="vulnerabilities-title">
    <PageHeader id="vulnerabilities-title" eyebrow="Scanner · Agent · Human · Retest" title="漏洞排查与闭环"
      description="接收真实扫描器发现，由漏洞研判智能体结合本地知识库给出建议；修复批准、变更实施和最终关闭始终由人工确认。"
      actions={<button type="button" onClick={() => setAttempt((value) => value + 1)}><RefreshCcw size={16} /> 刷新</button>} />
    {metrics && <div className="vulnerability-metrics" aria-label="漏洞闭环指标">
      <div><span>全部发现</span><strong>{metrics.total}</strong></div><div><span>未闭环</span><strong>{metrics.open}</strong></div>
      <div><span>严重未闭环</span><strong>{metrics.critical_open}</strong></div><div><span>待人工批准</span><strong>{metrics.awaiting_approval}</strong></div>
      <div><span>等待复测</span><strong>{metrics.verification_pending}</strong></div><div><span>已闭环</span><strong>{metrics.closed}</strong></div>
    </div>}
    {loading && <LoadingState title="正在加载漏洞台账" detail="读取扫描器发现与不可覆盖的闭环审计记录。" />}
    {error && !loading && <ErrorState title="漏洞闭环暂不可用" detail={error} action={<button type="button" onClick={() => setAttempt((value) => value + 1)}>重试</button>} />}
    {!loading && !error && items.length === 0 && <EmptyState title="暂无扫描器漏洞发现" detail="配置扫描器令牌并通过受控 API 导入结果后，发现会显示在这里；系统不会把告警中的 CVE 字样自动当成已确认漏洞。" />}
    {!loading && items.length > 0 && <div className="vulnerability-list">
      {items.map((item) => <article key={item.id} className={`vulnerability-card severity-${item.severity}`}>
        <header><div><p className="eyebrow">{item.scanner} · {item.asset_name}</p><h3>{item.cve_id}</h3></div><span>{statusLabel[item.status]}</span></header>
        <dl><div><dt>严重性</dt><dd>{item.severity.toUpperCase()}{item.cvss_score === null ? '' : ` · CVSS ${item.cvss_score}`}</dd></div>
          <div><dt>组件</dt><dd>{item.package_name ?? '未提供'}</dd></div><div><dt>当前版本</dt><dd>{item.installed_version ?? '待核对'}</dd></div><div><dt>修复版本</dt><dd>{item.fixed_version ?? '待核对'}</dd></div></dl>
        {item.latest_triage && <section className="agent-triage"><strong>漏洞研判智能体 · {String(item.latest_triage.details.priority ?? '待分级')}</strong>
          <p>{item.latest_triage.summary}</p><small>{item.latest_triage.details.agent_status === 'completed' ? `模型：${String(item.latest_triage.details.model)}` : '模型不可用时采用保守降级，必须人工核实。'}</small>
          <div><b>影响判断</b><p>{String(item.latest_triage.details.affected_assessment ?? '')}</p><b>修复建议</b><p>{String(item.latest_triage.details.remediation ?? '')}</p><b>复测标准</b><p>{String(item.latest_triage.details.verification ?? '')}</p></div>
        </section>}
        {['triaged', 'remediation_approved', 'remediation_in_progress', 'verification_pending'].includes(item.status) && <div className="vulnerability-action-form">
          {(item.status === 'remediation_approved' || item.status === 'remediation_in_progress') && <input value={changeTicket(item)} onChange={(event) => setTicket((old) => ({ ...old, [item.id]: event.target.value }))} placeholder="变更单号，例如 CHG-2026-001" />}
          <textarea value={rationale(item)} onChange={(event) => setNote((old) => ({ ...old, [item.id]: event.target.value }))} placeholder="至少 10 个字符，记录人工依据、实施情况或复测证据。" maxLength={1000} />
        </div>}
        <div className="vulnerability-actions">
          {item.status === 'new' && <button disabled={busy !== null} onClick={() => void run(item, 'triage', { business_context: null })}><ShieldAlert size={16} /> {busy === item.id ? '研判中…' : '启动智能体研判'}</button>}
          {item.status === 'triaged' && <><button disabled={disabled(item)} onClick={() => void run(item, 'decision', { outcome: 'approve_remediation', reason_code: 'confirmed_exposure', rationale: rationale(item), risk_expires_at: null })}><CheckCircle2 size={16} /> 批准修复</button>
            <button className="secondary-button" disabled={disabled(item)} onClick={() => void run(item, 'decision', { outcome: 'mark_not_affected', reason_code: 'version_not_affected', rationale: rationale(item), risk_expires_at: null })}>确认不受影响</button>
            <button className="secondary-button" disabled={disabled(item)} onClick={() => void run(item, 'decision', { outcome: 'accept_risk', reason_code: 'business_exception', rationale: rationale(item), risk_expires_at: new Date(Date.now() + 30 * 86400000).toISOString() })}>接受风险 30 天</button></>}
          {item.status === 'remediation_approved' && <button disabled={disabled(item, true)} onClick={() => void run(item, 'changes', { change_ticket: changeTicket(item), implementer: '人工操作员', planned_at: new Date().toISOString(), plan_summary: rationale(item) })}><Wrench size={16} /> 登记开始实施</button>}
          {item.status === 'remediation_in_progress' && <button disabled={disabled(item, true)} onClick={() => void run(item, 'implementation', { change_ticket: changeTicket(item), implementation_summary: rationale(item), evidence_references: [`change:${changeTicket(item)}`] })}>记录实施完成</button>}
          {item.status === 'verification_pending' && <><button disabled={disabled(item)} onClick={() => void run(item, 'verification', { result: 'passed', scanner: item.scanner, observed_version: item.fixed_version, evidence_references: [`retest:${item.external_id}`], summary: rationale(item) })}>复测通过并关闭</button>
            <button className="secondary-button" disabled={disabled(item)} onClick={() => void run(item, 'verification', { result: 'failed', scanner: item.scanner, observed_version: item.installed_version, evidence_references: [`retest:${item.external_id}`], summary: rationale(item) })}>复测失败，退回研判</button></>}
        </div>
        <details><summary>审计时间线（{item.events.length}）</summary><ol className="vulnerability-timeline">{item.events.map((event) => <li key={event.id}><strong>{eventLabel[event.event_type] ?? event.event_type}</strong><span>{new Date(event.created_at).toLocaleString('zh-CN')}</span><p>{event.summary}</p></li>)}</ol></details>
      </article>)}
    </div>}
  </section>
}
