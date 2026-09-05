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
}

function asCase(value: unknown): ReviewCase {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('告警服务返回了无效数据')
  const item = value as Record<string, unknown>
  const keys = ['id', 'tracking_id', 'alert_id', 'source', 'status', 'run_id', 'severity', 'rule_id', 'title', 'endpoint', 'created_at', 'updated_at']
  if (keys.some((key) => !(key in item)) || Object.keys(item).some((key) => !keys.includes(key))) throw new Error('告警服务返回了无效数据')
  if (typeof item.id !== 'string' || typeof item.tracking_id !== 'string' || typeof item.alert_id !== 'string' || item.source !== 'wazuh' || !['needs_review', 'investigated'].includes(String(item.status)) || (item.run_id !== null && typeof item.run_id !== 'string') || typeof item.severity !== 'number' || typeof item.rule_id !== 'string' || typeof item.title !== 'string' || typeof item.endpoint !== 'string' || typeof item.created_at !== 'string' || typeof item.updated_at !== 'string') throw new Error('告警服务返回了无效数据')
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

export function AlertsPage() {
  const navigate = useNavigate()
  const [items, setItems] = useState<ReviewCase[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [runningCase, setRunningCase] = useState<string | null>(null)

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setError(null)
    try { setItems(await listReviewCases(signal)) }
    catch (reason) { if (!signal?.aborted) setError(reason instanceof Error ? reason.message : '无法加载实时告警') }
    finally { if (!signal?.aborted) setLoading(false) }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void refresh(controller.signal)
    return () => controller.abort()
  }, [attempt, refresh])

  const investigate = async (item: ReviewCase) => {
    setRunningCase(item.id)
    setError(null)
    try { navigate(`/response?run_id=${encodeURIComponent(await investigateCase(item.id))}`) }
    catch (reason) { setError(reason instanceof Error ? reason.message : '无法启动智能体调查') }
    finally { setRunningCase(null) }
  }

  return <section aria-labelledby="alerts-title" className="page-card alerts-page">
    <PageHeader
      id="alerts-title"
      eyebrow="Wazuh · 人工复核队列"
      title="实时告警"
      description="达到阈值的 Wazuh 告警先进入人工复核队列；只有操作员点击启动，智能体才会调查并生成需再次审批的响应计划。"
      actions={<button type="button" onClick={() => setAttempt((value) => value + 1)}>刷新列表</button>}
    />
    {loading && <LoadingState title="正在加载实时告警" detail="正在读取本机 Wazuh Manager 已转发的高风险告警。" />}
    {error && !loading && <ErrorState title="无法加载实时告警" detail={error} action={<button type="button" onClick={() => setAttempt((value) => value + 1)}>重试</button>} />}
    {!loading && !error && items.length === 0 && <EmptyState title="暂无待人工复核告警" detail="当 Wazuh 发现等级达到 12 的新告警时，会自动出现在这里。" />}
    {!loading && !error && items.length > 0 && <div className="alert-case-list" role="list">
      {items.map((item) => <article className="alert-case" key={item.id} role="listitem">
        <header><div><p className="eyebrow">{item.tracking_id} · Wazuh 规则 {item.rule_id}</p><h3>{item.title}</h3></div><span className="alert-case__status">{item.status === 'investigated' ? '已生成计划' : '待人工复核'}</span></header>
        <dl><div><dt>终端</dt><dd>{item.endpoint}</dd></div><div><dt>告警等级</dt><dd>Level {item.severity}</dd></div><div><dt>来源</dt><dd>Wazuh</dd></div><div><dt>接收时间</dt><dd>{formatTime(item.created_at)}</dd></div></dl>
        <div className="alert-case__actions"><p className="alert-case__note">{item.status === 'investigated' ? '调查运行已创建；计划接受、动作审批和执行仍由操作员分别决定。' : '当前仅保留规范化告警证据，尚未启动智能体或处置操作。'}</p>{item.run_id ? <Link to={`/response?run_id=${encodeURIComponent(item.run_id)}`}>进入处置中心</Link> : <button type="button" disabled={runningCase !== null} onClick={() => void investigate(item)}>{runningCase === item.id ? '智能体分析中…' : '启动智能体调查'}</button>}</div>
      </article>)}
    </div>}
  </section>
}
