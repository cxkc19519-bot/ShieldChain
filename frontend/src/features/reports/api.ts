import { getCollaborationTrajectory } from '../agents/api'
import { getReactTrajectory } from '../agents/reactApi'
import { getAudit, getIncident, getInvestigation } from '../investigation/api'
import { getToolTrace } from '../tools/api'
import type { HistoricalReport, ReportBundle, ReportSourceName, ReportSourceState } from './types'

type Settled<T> = { value: T | null; state: ReportSourceState }

function message(value: unknown): string {
  return value instanceof Error ? value.message : '公开数据源不可用'
}

async function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  try {
    return { value: await promise, state: { status: 'available', message: '公开投影可用' } }
  } catch (error) {
    return { value: null, state: { status: 'unavailable', message: message(error) } }
  }
}

function missing(label: string): Settled<never> {
  return { value: null, state: { status: 'unavailable', message: `未提供${label}` } }
}

function aborted(signal?: AbortSignal): never {
  throw signal?.reason ?? new DOMException('Request aborted', 'AbortError')
}

export async function loadReportBundle(
  selection: { incidentId: string | null; runId: string | null },
  signal?: AbortSignal,
): Promise<ReportBundle> {
  const incidentPromise = selection.incidentId ? settle(getIncident(selection.incidentId, signal)) : Promise.resolve(missing('事件 ID'))
  const auditPromise = selection.incidentId ? settle(getAudit(selection.incidentId, signal)) : Promise.resolve(missing('事件 ID'))
  const investigationPromise = selection.runId ? settle(getInvestigation(selection.runId, signal)) : Promise.resolve(missing('运行 ID'))
  const collaborationPromise = selection.runId ? settle(getCollaborationTrajectory(selection.runId, signal)) : Promise.resolve(missing('运行 ID'))
  const toolsPromise = selection.runId ? settle(getToolTrace(selection.runId, signal)) : Promise.resolve(missing('运行 ID'))
  const reactPromise = selection.runId ? settle(getReactTrajectory(selection.runId, signal)) : Promise.resolve(missing('运行 ID'))

  const [incident, investigation, audit, collaboration, tools, react] = await Promise.all([
    incidentPromise, investigationPromise, auditPromise, collaborationPromise, toolsPromise, reactPromise,
  ])
  if (signal?.aborted) aborted(signal)
  const sources = Object.fromEntries(([
    ['incident', incident.state], ['investigation', investigation.state], ['audit', audit.state],
    ['agents', collaboration.state], ['tools', tools.state], ['react', react.state],
  ] as [ReportSourceName, ReportSourceState][])) as Record<ReportSourceName, ReportSourceState>
  return {
    incident: incident.value,
    investigation: investigation.value,
    audit: audit.value,
    collaboration: collaboration.value,
    tools: tools.value,
    react: react.value,
    sources,
  }
}

function reportRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('历史报告服务返回了无效响应')
  return value as Record<string, unknown>
}

function reportText(value: unknown): string {
  if (typeof value !== 'string') throw new Error('历史报告服务返回了无效响应')
  return value
}

function historicalReport(value: unknown): HistoricalReport {
  const item = reportRecord(value)
  const keys = ['run_id', 'run_tracking_id', 'incident_id', 'incident_tracking_id', 'status', 'threat_label', 'endpoint', 'created_at', 'updated_at', 'completed_at']
  if (keys.some((key) => !(key in item)) || Object.keys(item).some((key) => !keys.includes(key))) throw new Error('历史报告服务返回了无效响应')
  return {
    run_id: reportText(item.run_id), run_tracking_id: reportText(item.run_tracking_id),
    incident_id: reportText(item.incident_id), incident_tracking_id: reportText(item.incident_tracking_id),
    status: reportText(item.status), threat_label: reportText(item.threat_label), endpoint: reportText(item.endpoint),
    created_at: reportText(item.created_at), updated_at: reportText(item.updated_at),
    completed_at: item.completed_at === null ? null : reportText(item.completed_at),
  }
}

export async function listHistoricalReports(signal?: AbortSignal): Promise<HistoricalReport[]> {
  const response = await fetch('/api/v1/reports/history', { method: 'GET', signal })
  let body: unknown
  try { body = await response.json() } catch { throw new Error('历史报告服务返回了无效响应') }
  if (!response.ok) throw new Error('历史报告加载失败，请稍后重试。')
  const payload = reportRecord(body)
  if (Object.keys(payload).length !== 1 || !Array.isArray(payload.reports)) throw new Error('历史报告服务返回了无效响应')
  return payload.reports.map(historicalReport)
}
export async function deleteHistoricalReport(runId: string): Promise<void> {
  const response = await fetch(`/api/v1/reports/history/${encodeURIComponent(runId)}`, { method: 'DELETE' })
  if (!response.ok) throw new Error('删除历史报告失败，请稍后重试。')
}