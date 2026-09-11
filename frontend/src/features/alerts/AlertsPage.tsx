import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import './alerts.css'

type ReviewCase = {
  id: string
  tracking_id: string
  alert_id: string
  source: 'wazuh'
  status: 'needs_review' | 'investigating' | 'investigated' | 'investigation_failed'
  run_id: string | null
  severity: number
  rule_id: string
  title: string
  endpoint: string
  created_at: string
  updated_at: string
  triage_assessment: { run_id: string; agent_name: '告警分诊智能体'; model: string | null; summary: string; decision_reason: string; limitation: string } | null
  disposition: CaseDisposition | null
}

type CaseDisposition = {
  id: string; case_id: string; run_id: string
  decision: 'false_positive' | 'true_positive' | 'needs_more_evidence'
  reason_code: string; rationale: string
  suppression_scope: 'none' | 'same_rule_endpoint' | 'same_rule'
  suppression_status: 'not_requested' | 'proposed_only' | 'active' | 'expired' | 'revoked'
  suppression_expires_at: string | null; reviewer_id: string; created_at: string
}

type FalsePositiveMetrics = {
  reviewed_cases: number; false_positives: number; true_positives: number
  needs_more_evidence: number; false_positive_rate: number | null; proposed_suppressions: number
  active_suppressions: number; suppressed_alerts: number
}

type SuppressedAlert = {
  id: string; external_id: string; occurred_at: string; severity: number; rule_id: string
  title: string; agent_name: string | null; received_at: string
  suppression: {
    id: string; policy_id: string; scope: 'same_rule_endpoint' | 'same_rule'
    rule_id: string; endpoint: string; matched_at: string; expires_at: string
  }
}

type DemoReplayStatus = {
  state: 'idle' | 'running' | 'completed' | 'failed'
  sample: { id: string; title: string } | null
  run_id: string | null
  alert_count?: number
  reason?: string
}

function asCase(value: unknown): ReviewCase {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('告警服务返回了无效数据')
  const item = value as Record<string, unknown>
  const keys = ['id', 'tracking_id', 'alert_id', 'source', 'status', 'run_id', 'severity', 'rule_id', 'title', 'endpoint', 'created_at', 'updated_at', 'triage_assessment', 'disposition']
  if (keys.some((key) => !(key in item)) || Object.keys(item).some((key) => !keys.includes(key))) throw new Error('告警服务返回了无效数据')
  if (typeof item.id !== 'string' || typeof item.tracking_id !== 'string' || typeof item.alert_id !== 'string' || item.source !== 'wazuh' || !['needs_review', 'investigating', 'investigated', 'investigation_failed'].includes(String(item.status)) || (item.run_id !== null && typeof item.run_id !== 'string') || typeof item.severity !== 'number' || typeof item.rule_id !== 'string' || typeof item.title !== 'string' || typeof item.endpoint !== 'string' || typeof item.created_at !== 'string' || typeof item.updated_at !== 'string' || (item.triage_assessment !== null && (typeof item.triage_assessment !== 'object' || Array.isArray(item.triage_assessment))) || (item.disposition !== null && (typeof item.disposition !== 'object' || Array.isArray(item.disposition)))) throw new Error('告警服务返回了无效数据')
  return item as ReviewCase
}

async function listReviewCases(signal?: AbortSignal): Promise<ReviewCase[]> {
  const response = await fetch('/api/v1/integrations/wazuh/cases', { method: 'GET', signal })
  let payload: unknown
  try { payload = await response.json() } catch { throw new Error('告警服务返回了无效响应') }
  if (!response.ok || typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('无法加载实时告警')
  const items = (payload as Record<string, unknown>).items
  if (!Array.isArray(items)) throw new Error('告警服务返回了无效响应')
  return items.map(asCase)
}

async function listSuppressedAlerts(signal?: AbortSignal): Promise<SuppressedAlert[]> {
  const response = await fetch('/api/v1/integrations/wazuh/alerts?limit=200', { signal })
  const payload: unknown = await response.json()
  if (!response.ok || typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('无法加载抑制记录')
  const items = (payload as { items?: unknown }).items
  if (!Array.isArray(items)) throw new Error('告警服务返回了无效抑制记录')
  return items.filter((item): item is SuppressedAlert => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return false
    const value = item as Record<string, unknown>
    return typeof value.id === 'string' && typeof value.rule_id === 'string' && typeof value.title === 'string'
      && typeof value.received_at === 'string' && typeof value.suppression === 'object' && value.suppression !== null
  })
}

function formatTime(value: string): string {
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false })
}

async function loadMetrics(signal?: AbortSignal): Promise<FalsePositiveMetrics> {
  const response = await fetch('/api/v1/integrations/wazuh/false-positive-metrics', { signal })
  const payload: unknown = await response.json()
  if (!response.ok || typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('无法加载误报治理统计')
  return payload as FalsePositiveMetrics
}

async function submitDisposition(caseId: string, input: {
  decision: CaseDisposition['decision']; reason_code: string; rationale: string
  suppression_scope: CaseDisposition['suppression_scope']; suppression_expires_at: string | null
}): Promise<void> {
  const response = await fetch(`/api/v1/integrations/wazuh/cases/${encodeURIComponent(caseId)}/disposition`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
  })
  let payload: unknown
  try { payload = await response.json() } catch { throw new Error('误报治理服务返回了无效响应') }
  if (!response.ok) {
    const detail = typeof payload === 'object' && payload !== null && !Array.isArray(payload) ? (payload as { error?: { message?: unknown } }).error?.message : null
    throw new Error(typeof detail === 'string' ? detail : '无法保存人工定性')
  }
}

async function approveSuppression(caseId: string): Promise<void> {
  const response = await fetch(`/api/v1/integrations/wazuh/cases/${encodeURIComponent(caseId)}/suppression/approve`, { method: 'POST' })
  let payload: unknown = null
  try { payload = await response.json() } catch { /* use fallback message */ }
  if (response.ok) return
  const detail = typeof payload === 'object' && payload !== null && !Array.isArray(payload) ? (payload as { error?: { message?: unknown } }).error?.message : null
  throw new Error(typeof detail === 'string' ? detail : '无法批准抑制策略')
}

async function deleteReviewCase(caseId: string): Promise<void> {
  const response = await fetch(`/api/v1/integrations/wazuh/cases/${encodeURIComponent(caseId)}`, {
    method: 'DELETE',
  })
  if (response.ok) return
  let payload: unknown = null
  try { payload = await response.json() } catch { /* use fallback message */ }
  const detail = typeof payload === 'object' && payload !== null && !Array.isArray(payload) ? (payload as { error?: { message?: unknown } }).error?.message : null
  throw new Error(typeof detail === 'string' ? detail : '删除告警失败')
}

async function startDemoReplay(): Promise<DemoReplayStatus> {
  const response = await fetch('/api/v1/nta/demo-replay/start', { method: 'POST' })
  const payload: unknown = await response.json()
  if (!response.ok || typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('演示回放服务不可用')
  }
  return payload as DemoReplayStatus
}

async function getDemoReplayStatus(): Promise<DemoReplayStatus> {
  const response = await fetch('/api/v1/nta/demo-replay/status')
  const payload: unknown = await response.json()
  if (!response.ok || typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('无法读取演示回放状态')
  }
  return payload as DemoReplayStatus
}

export function AlertsPage() {
  const [items, setItems] = useState<ReviewCase[]>([])
  const [suppressedAlerts, setSuppressedAlerts] = useState<SuppressedAlert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [metrics, setMetrics] = useState<FalsePositiveMetrics | null>(null)
  const [reviewingCase, setReviewingCase] = useState<string | null>(null)
  const [decision, setDecision] = useState<CaseDisposition['decision']>('needs_more_evidence')
  const [reasonCode, setReasonCode] = useState('insufficient_context')
  const [rationale, setRationale] = useState('')
  const [suppressionScope, setSuppressionScope] = useState<CaseDisposition['suppression_scope']>('none')
  const [saving, setSaving] = useState(false)
  const [approvingCase, setApprovingCase] = useState<string | null>(null)
  const [demoReplay, setDemoReplay] = useState<DemoReplayStatus | null>(null)
  const [startingDemoReplay, setStartingDemoReplay] = useState(false)
  const [deletingCase, setDeletingCase] = useState<string | null>(null)

  const refresh = useCallback(async (signal?: AbortSignal, quiet = false) => {
    if (!quiet) { setLoading(true); setError(null) }
    try {
      const [cases, nextMetrics, suppressed] = await Promise.all([listReviewCases(signal), loadMetrics(signal), listSuppressedAlerts(signal)])
      setItems(cases)
      setMetrics(nextMetrics)
      setSuppressedAlerts(suppressed)
    }
    catch (reason) { if (!signal?.aborted) setError(reason instanceof Error ? reason.message : '无法加载实时告警') }
    finally { if (!signal?.aborted && !quiet) setLoading(false) }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void refresh(controller.signal)
    return () => controller.abort()
  }, [attempt, refresh])

  useEffect(() => {
    if (!items.some((item) => item.status === 'needs_review' || item.status === 'investigating')) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => void refresh(controller.signal, true), 2500)
    return () => { window.clearTimeout(timer); controller.abort() }
  }, [items, refresh])

  useEffect(() => {
    if (demoReplay?.state !== 'running') return
    const timer = window.setTimeout(() => {
      void getDemoReplayStatus().then((next) => {
        setDemoReplay(next)
        if (next.state === 'completed') setAttempt((value) => value + 1)
      }).catch((reason) => setError(reason instanceof Error ? reason.message : '无法读取演示回放状态'))
    }, 1500)
    return () => window.clearTimeout(timer)
  }, [demoReplay?.state])

  const runDemoReplay = async () => {
    setStartingDemoReplay(true)
    setError(null)
    try { setDemoReplay(await startDemoReplay()) }
    catch (reason) { setError(reason instanceof Error ? reason.message : '演示回放服务不可用') }
    finally { setStartingDemoReplay(false) }
  }

  const openReview = (item: ReviewCase) => {
    setReviewingCase(item.id)
    setDecision('needs_more_evidence')
    setReasonCode('insufficient_context')
    setRationale('')
    setSuppressionScope('none')
  }

  const saveDisposition = async (item: ReviewCase) => {
    setSaving(true)
    setError(null)
    try {
      const expiresAt = suppressionScope === 'none' ? null : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      await submitDisposition(item.id, {
        decision, reason_code: reasonCode, rationale,
        suppression_scope: decision === 'false_positive' ? suppressionScope : 'none',
        suppression_expires_at: decision === 'false_positive' ? expiresAt : null,
      })
      setReviewingCase(null)
      setAttempt((value) => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '无法保存人工定性') }
    finally { setSaving(false) }
  }

  const removeCase = async (item: ReviewCase) => {
    const reportNotice = item.run_id
      ? '对应的安全运营报告及服务器上的 HTML、Markdown 和元数据文件也会一并删除；底层调查审计仍保留。'
      : '该告警尚未生成安全运营报告；底层接收与调查审计仍保留。'
    if (!window.confirm(`确定从告警列表删除“${item.tracking_id}”吗？${reportNotice}`)) return
    setDeletingCase(item.id)
    setError(null)
    try {
      await deleteReviewCase(item.id)
      setItems((current) => current.filter((entry) => entry.id !== item.id))
      setReviewingCase((current) => current === item.id ? null : current)
      setAttempt((value) => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '删除告警失败') }
    finally { setDeletingCase(null) }
  }

  const activateSuppression = async (item: ReviewCase) => {
    const target = item.disposition?.suppression_scope === 'same_rule_endpoint'
      ? `规则 ${item.rule_id} 在终端 ${item.endpoint}`
      : `规则 ${item.rule_id} 的全部终端`
    if (!window.confirm(`批准后，${target}产生的新告警将在有效期内自动标记为误报并跳过智能体调查。是否继续？`)) return
    setApprovingCase(item.id)
    setError(null)
    try {
      await approveSuppression(item.id)
      setAttempt((value) => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '无法批准抑制策略') }
    finally { setApprovingCase(null) }
  }

  const decisionLabel = (item: ReviewCase) => {
    if (item.disposition?.decision === 'false_positive') return '已确认误报'
    if (item.disposition?.decision === 'true_positive') return '已确认有效'
    if (item.disposition?.decision === 'needs_more_evidence') return '需要补充证据'
    if (item.status === 'investigated') return '待人工定性'
    if (item.status === 'investigation_failed') return '调查已终止'
    return item.status === 'investigating' ? '智能体调查中' : '等待自动调查'
  }

  const replayStatus = demoReplay?.state === 'running'
    ? '正在回放'
    : demoReplay?.state === 'completed'
      ? `回放完成：已导入 ${demoReplay.alert_count ?? 0} 条告警`
      : demoReplay?.state === 'failed'
        ? '回放失败，请查看服务器运行记录'
        : '回放服务已就绪'

  return <section aria-labelledby="alerts-title" className="page-card alerts-page">
    <PageHeader id="alerts-title" title="实时告警" centered />
    <section className="replay-control" aria-labelledby="replay-control-title">
      <div className="replay-control__summary">
        <div className="replay-control__heading">
          <div>
            <p className="eyebrow">隔离流量回放</p>
            <h2 id="replay-control-title">流量回放控制</h2>
          </div>
          <span className={`replay-control__status replay-control__status--${demoReplay?.state ?? 'idle'}`} role="status">{replayStatus}</span>
        </div>
        <p>从服务器白名单随机选择已验收流量样本，触发一轮完整的自动化安全运营闭环。</p>
        <ol className="replay-control__flow" aria-label="自动化安全运营流程">
          {['流量回放', '产生告警', '自动调查', '自动处置', '生成报告'].map((step, index) => <li key={step}><span>{index + 1}</span>{step}</li>)}
        </ol>
      </div>
      <button className="replay-control__button" type="button" disabled={startingDemoReplay || demoReplay?.state === 'running'} onClick={() => void runDemoReplay()}>
        {startingDemoReplay || demoReplay?.state === 'running' ? '回放运行中…' : '启动随机回放'}
      </button>
    </section>
    {metrics && <div className="false-positive-metrics" aria-label="误报治理统计">
      <div><span>已定性案件</span><strong>{metrics.reviewed_cases}</strong></div>
      <div><span>确认误报</span><strong>{metrics.false_positives}</strong></div>
      <div><span>确认有效</span><strong>{metrics.true_positives}</strong></div>
      <div><span>误报率</span><strong>{metrics.false_positive_rate === null ? '待积累' : `${(metrics.false_positive_rate * 100).toFixed(1)}%`}</strong></div>
      <div><span>待审批策略</span><strong>{metrics.proposed_suppressions}</strong></div>
      <div><span>生效策略</span><strong>{metrics.active_suppressions}</strong></div>
      <div><span>已抑制告警</span><strong>{metrics.suppressed_alerts}</strong></div>
    </div>}
    {suppressedAlerts.length > 0 && <section className="suppressed-alerts" aria-labelledby="suppressed-alerts-title">
      <div className="alerts-list-toolbar"><h2 id="suppressed-alerts-title">自动抑制记录</h2><span>原始告警已保留，未启动智能体调查</span></div>
      <div className="suppressed-alert-list">
        {suppressedAlerts.map((alert) => <article className="suppressed-alert" key={alert.id}>
          <div><p className="eyebrow">Wazuh 规则 {alert.rule_id} · {alert.suppression.endpoint}</p><h3>{alert.title}</h3><small>策略有效至 {formatTime(alert.suppression.expires_at)}</small></div>
          <span>已自动标记误报</span>
        </article>)}
      </div>
    </section>}
    <div className="alerts-list-toolbar"><h2>告警列表</h2><button type="button" onClick={() => setAttempt((value) => value + 1)}>刷新列表</button></div>
    {loading && <LoadingState title="正在加载实时告警" detail="正在读取本机 Wazuh Manager 已转发的高风险告警。" />}
    {error && !loading && <ErrorState title="无法加载实时告警" detail={error} action={<button type="button" onClick={() => setAttempt((value) => value + 1)}>重试</button>} />}
    {!loading && !error && items.length === 0 && <EmptyState title="暂无待人工复核告警" detail="当 Wazuh 发现等级达到 12 的新告警时，会自动出现在这里。" />}
    {!loading && !error && items.length > 0 && <div className="alert-case-list" role="list">
      {items.map((item) => <article className="alert-case" key={item.id} role="listitem">
        <header><div><p className="eyebrow">{item.tracking_id} · Wazuh 规则 {item.rule_id}</p><h3>{item.title}</h3></div><span className="alert-case__status">{decisionLabel(item)}</span></header>
        <dl><div><dt>终端</dt><dd>{item.endpoint}</dd></div><div><dt>告警等级</dt><dd>Level {item.severity}</dd></div><div><dt>来源</dt><dd>Wazuh</dd></div><div><dt>接收时间</dt><dd>{formatTime(item.created_at)}</dd></div></dl>
        {item.triage_assessment && <div className="triage-assessment"><strong>{item.triage_assessment.agent_name}</strong><p>{item.triage_assessment.summary}</p><small>{item.triage_assessment.limitation}</small></div>}
        {item.disposition && <div className="case-disposition"><strong>最近一次人工定性</strong><p>{item.disposition.rationale}</p><small>{item.disposition.suppression_status === 'proposed_only' ? '限时抑制策略等待人工审批。' : item.disposition.suppression_status === 'active' ? '限时抑制策略已批准并在告警入口生效。' : item.disposition.suppression_status === 'expired' ? '抑制策略已到期。' : item.disposition.suppression_status === 'revoked' ? '抑制策略已被后续审批替换。' : '未提出规则抑制。'} · {formatTime(item.disposition.created_at)}</small>{item.disposition.suppression_status === 'proposed_only' && <div className="case-disposition__actions"><button type="button" disabled={approvingCase === item.id} onClick={() => void activateSuppression(item)}>{approvingCase === item.id ? '正在启用…' : '批准并启用抑制'}</button></div>}</div>}
        {reviewingCase === item.id && <div className="disposition-form">
          <label>人工结论<select value={decision} onChange={(event) => { const value = event.target.value as CaseDisposition['decision']; setDecision(value); setReasonCode(value === 'false_positive' ? 'expected_activity' : value === 'true_positive' ? 'confirmed_malicious' : 'insufficient_context'); if (value !== 'false_positive') setSuppressionScope('none') }}>
            <option value="needs_more_evidence">证据不足</option><option value="false_positive">确认误报</option><option value="true_positive">确认有效告警</option>
          </select></label>
          <label>原因<select value={reasonCode} onChange={(event) => setReasonCode(event.target.value)}>
            {decision === 'needs_more_evidence' && <option value="insufficient_context">上下文不足</option>}
            {decision === 'false_positive' && <><option value="expected_activity">预期业务活动</option><option value="authorized_test">授权测试</option><option value="duplicate_detection">重复检测</option><option value="rule_too_broad">规则范围过宽</option></>}
            {decision === 'true_positive' && <option value="confirmed_malicious">已确认恶意</option>}
            <option value="other">其他</option>
          </select></label>
          <label className="disposition-form__wide">复核依据<textarea value={rationale} minLength={1} maxLength={1000} onChange={(event) => setRationale(event.target.value)} placeholder="填写核对过的日志、资产或业务背景。" /></label>
          {decision === 'false_positive' && <label className="disposition-form__wide">抑制建议<select value={suppressionScope} onChange={(event) => setSuppressionScope(event.target.value as CaseDisposition['suppression_scope'])}>
            <option value="none">不建议抑制</option><option value="same_rule_endpoint">同终端 + 同规则，建议抑制 7 天</option><option value="same_rule">同规则全局，建议抑制 7 天</option>
          </select></label>}
          <p className="alert-case__note disposition-form__wide">保存后记录人工结论和抑制建议。</p>
          <div className="disposition-form__actions"><button type="button" className="secondary-button" onClick={() => setReviewingCase(null)}>取消</button><button type="button" disabled={saving || rationale.trim().length === 0} onClick={() => void saveDisposition(item)}>{saving ? '保存中…' : '保存人工定性'}</button></div>
        </div>}
        <div className="alert-case__actions"><p className="alert-case__note">{item.status === 'investigated' ? '智能体调查已完成，调查、处置与验证结果已写入安全运营报告。' : item.status === 'investigation_failed' ? '该任务已经终止或超时，并未继续占用模型；告警证据仍被保留。' : '告警已自动调用智能体调查，页面会在调查完成后更新。'}</p><div className="alert-case__buttons">{item.status === 'investigated' && item.run_id ? <><Link to="/operations-report">查看安全运营报告</Link><button type="button" onClick={() => openReview(item)}>人工定性</button></> : <span className="alert-case__pending" role="status">{item.status === 'investigation_failed' ? '智能体调查已终止' : '智能体自动调查中…'}</span>}<button className="danger-button" type="button" disabled={deletingCase === item.id || item.status === 'investigating'} title={item.status === 'investigating' ? '智能体调查完成后才能删除' : undefined} onClick={() => void removeCase(item)}>{deletingCase === item.id ? '正在删除…' : '删除告警'}</button></div></div>
      </article>)}
    </div>}
  </section>
}
