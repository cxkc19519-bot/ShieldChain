import { getCollaborationTrajectory } from '../agents/api'
import { getReactTrajectory } from '../agents/reactApi'
import { getAudit, getIncident, getInvestigation } from '../investigation/api'
import { getToolTrace } from '../tools/api'
import type { ReportBundle, ReportSourceName, ReportSourceState } from './types'

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
