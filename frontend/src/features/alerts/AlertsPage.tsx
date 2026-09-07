import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import './alerts.css'

type ReviewCase = {
  id: string
  tracking_id: string
  alert_id: string
  source: 'wazuh'
  status: 'needs_review' | 'investigated'
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
  suppression_status: 'not_requested' | 'proposed_only'
  suppression_expires_at: string | null; reviewer_id: string; created_at: string
}

type FalsePositiveMetrics = {
  reviewed_cases: number; false_positives: number; true_positives: number
  needs_more_evidence: number; false_positive_rate: number | null; proposed_suppressions: number
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
  if (typeof item.id !== 'string' || typeof item.tracking_id !== 'string' || typeof item.alert_id !== 'string' || item.source !== 'wazuh' || !['needs_review', 'investigated'].includes(String(item.status)) || (item.run_id !== null && typeof item.run_id !== 'string') || typeof item.severity !== 'number' || typeof item.rule_id !== 'string' || typeof item.title !== 'string' || typeof item.endpoint !== 'string' || typeof item.created_at !== 'string' || typeof item.updated_at !== 'string' || (item.triage_assessment !== null && (typeof item.triage_assessment !== 'object' || Array.isArray(item.triage_assessment))) || (item.disposition !== null && (typeof item.disposition !== 'object' || Array.isArray(item.disposition)))) throw new Error('告警服务返回了无效数据')
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

async function investigateCase(caseId: string): Promise<string> {
  const response = await fetch(`/api/v1/integrations/wazuh/cases/${encodeURIComponent(caseId)}/investigate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rule_ttl_seconds: 60 }),
  })
  let payload: unknown
  try { payload = await response.json() } catch { throw new Error('调查服务返回了无效响应') }
  if (!response.ok || typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    const error = typeof payload === 'object' && payload !== null && !Array.isArray(payload) ? (payload as Record<string, unknown>).error : null
    const message = typeof error === 'object' && error !== null && !Array.isArray(error) && typeof (error as Record<string, unknown>).message === 'string' ? String((error as Record<string, unknown>).message) : '无法启动智能体调查'
    throw new Error(message)
  }
  const runId = (payload as Record<string, unknown>).run_id
  if (typeof runId !== 'string') throw new Error('调查结果缺少运行 ID')
  return runId
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
  const navigate = useNavigate()
  const [items, setItems] = useState<ReviewCase[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [runningCase, setRunningCase] = useState<string | null>(null)
  const [metrics, setMetrics] = useState<FalsePositiveMetrics | null>(null)
  const [reviewingCase, setReviewingCase] = useState<string | null>(null)
  const [decision, setDecision] = useState<CaseDisposition['decision']>('needs_more_evidence')
  const [reasonCode, setReasonCode] = useState('insufficient_context')
  const [rationale, setRationale] = useState('')
  const [suppressionScope, setSuppressionScope] = useState<CaseDisposition['suppression_scope']>('none')
  const [saving, setSaving] = useState(false)
  const [demoReplay, setDemoReplay] = useState<DemoReplayStatus | null>(null)
  const [startingDemoReplay, setStartingDemoReplay] = useState(false)

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setError(null)
    try {
      const [cases, nextMetrics] = await Promise.all([listReviewCases(signal), loadMetrics(signal)])
      setItems(cases)
      setMetrics(nextMetrics)
    }
    catch (reason) { if (!signal?.aborted) setError(reason instanceof Error ? reason.message : '无法加载实时告警') }
    finally { if (!signal?.aborted) setLoading(false) }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void refresh(controller.signal)
    return () => controller.abort()
  }, [attempt, refresh])

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

  const investigate = async (item: ReviewCase) => {
    setRunningCase(item.id)
    setError(null)
    try { navigate(`/response?run_id=${encodeURIComponent(await investigateCase(item.id))}`) }
    catch (reason) { setError(reason instanceof Error ? reason.message : '无法启动智能体调查') }
    finally { setRunningCase(null) }
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

  const decisionLabel = (item: ReviewCase) => {
    if (item.disposition?.decision === 'false_positive') return '已确认误报'
    if (item.disposition?.decision === 'true_positive') return '已确认有效'
    if (item.disposition?.decision === 'needs_more_evidence') return '需要补充证据'
    return item.status === 'investigated' ? '待人工定性' : '待人工复核'
  }

  return <section aria-labelledby="alerts-title" className="page-card alerts-page">
    <PageHeader
      id="alerts-title"
      eyebrow="Wazuh · 人工复核队列"
      title="实时告警"
      description="达到阈值的 Wazuh 告警先进入人工复核队列；只有操作员点击启动，智能体才会调查并生成需再次审批的响应计划。"
      actions={<div className="alert-case__buttons"><button type="button" disabled={startingDemoReplay || demoReplay?.state === 'running'} onClick={() => void runDemoReplay}>{startingDemoReplay || demoReplay?.state === 'running' ? '隔离回放中…' : '随机演示回放'}</button><button type="button" onClick={() => setAttempt((value) => value + 1)}>刷新列表</button></div>}
    />
    {demoReplay && <p className="alert-case__note" role="status">{demoReplay.state === 'running' ? `正在隔离回放：${demoReplay.sample?.title ?? '已验收样本'}。` : demoReplay.state === 'completed' ? `回放完成：${demoReplay.sample?.title ?? '样本'}，已导入 ${demoReplay.alert_count ?? 0} 条告警。` : demoReplay.state === 'failed' ? '演示回放失败；未导入告警，请查看服务器运行记录。' : '演示回放服务已就绪。'}</p>}
    {metrics && <div className="false-positive-metrics" aria-label="误报治理统计">
      <div><span>已定性案件</span><strong>{metrics.reviewed_cases}</strong></div>
      <div><span>确认误报</span><strong>{metrics.false_positives}</strong></div>
      <div><span>确认有效</span><strong>{metrics.true_positives}</strong></div>
      <div><span>误报率</span><strong>{metrics.false_positive_rate === null ? '待积累' : `${(metrics.false_positive_rate * 100).toFixed(1)}%`}</strong></div>
      <div><span>抑制建议</span><strong>{metrics.proposed_suppressions}</strong></div>
    </div>}
    {loading && <LoadingState title="正在加载实时告警" detail="正在读取本机 Wazuh Manager 已转发的高风险告警。" />}
    {error && !loading && <ErrorState title="无法加载实时告警" detail={error} action={<button type="button" onClick={() => setAttempt((value) => value + 1)}>重试</button>} />}
    {!loading && !error && items.length === 0 && <EmptyState title="暂无待人工复核告警" detail="当 Wazuh 发现等级达到 12 的新告警时，会自动出现在这里。" />}
    {!loading && !error && items.length > 0 && <div className="alert-case-list" role="list">
      {items.map((item) => <article className="alert-case" key={item.id} role="listitem">
        <header><div><p className="eyebrow">{item.tracking_id} · Wazuh 规则 {item.rule_id}</p><h3>{item.title}</h3></div><span className="alert-case__status">{decisionLabel(item)}</span></header>
        <dl><div><dt>终端</dt><dd>{item.endpoint}</dd></div><div><dt>告警等级</dt><dd>Level {item.severity}</dd></div><div><dt>来源</dt><dd>Wazuh</dd></div><div><dt>接收时间</dt><dd>{formatTime(item.created_at)}</dd></div></dl>
        {item.triage_assessment && <div className="triage-assessment"><strong>{item.triage_assessment.agent_name}</strong><p>{item.triage_assessment.summary}</p><small>{item.triage_assessment.limitation}</small></div>}
        {item.disposition && <div className="case-disposition"><strong>最近一次人工定性</strong><p>{item.disposition.rationale}</p><small>{item.disposition.suppression_status === 'proposed_only' ? '已生成限时抑制建议；尚未写入 Wazuh。' : '未提出规则抑制。'} · {formatTime(item.disposition.created_at)}</small></div>}
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
          <label className="disposition-form__wide">复核依据<textarea value={rationale} maxLength={1000} onChange={(event) => setRationale(event.target.value)} placeholder="至少 10 个字符，说明核对了哪些日志、资产或业务背景。" /></label>
          {decision === 'false_positive' && <label className="disposition-form__wide">抑制建议<select value={suppressionScope} onChange={(event) => setSuppressionScope(event.target.value as CaseDisposition['suppression_scope'])}>
            <option value="none">不建议抑制</option><option value="same_rule_endpoint">同终端 + 同规则，建议抑制 7 天</option><option value="same_rule">同规则全局，建议抑制 7 天</option>
          </select></label>}
          <p className="alert-case__note disposition-form__wide">保存只记录人工结论和抑制建议，不会删除告警或自动修改 Wazuh 规则。</p>
          <div className="disposition-form__actions"><button type="button" className="secondary-button" onClick={() => setReviewingCase(null)}>取消</button><button type="button" disabled={saving || rationale.trim().length < 10} onClick={() => void saveDisposition(item)}>{saving ? '保存中…' : '保存人工定性'}</button></div>
        </div>}
        <div className="alert-case__actions"><p className="alert-case__note">{item.status === 'investigated' ? '智能体调查已完成；误报结论、计划接受和动作审批仍由操作员决定。' : '当前仅保留规范化告警证据，尚未启动智能体或处置操作。'}</p><div className="alert-case__buttons">{item.run_id ? <><Link to={`/response?run_id=${encodeURIComponent(item.run_id)}`}>进入处置中心</Link><button type="button" onClick={() => openReview(item)}>人工定性</button></> : <button type="button" disabled={runningCase !== null} onClick={() => void investigate(item)}>{runningCase === item.id ? '智能体分析中…' : '启动智能体调查'}</button>}</div></div>
      </article>)}
    </div>}
  </section>
}
