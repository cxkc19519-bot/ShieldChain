import type {
  AssessmentView,
  AuditEventView,
  AuditResponse,
  EvidenceView,
  IncidentResponse,
  IncidentView,
  InvestigationMode,
  InvestigationResponse,
  InvestigationStatus,
  InvestigationStep,
  JsonObject,
  JsonScalar,
  ResetSimulationResponse,
  RunSummaryView,
  SimulationView,
  ToolResultView,
  VerificationView,
} from './types'

const API_ROOT = '/api/v1'
const REQUEST_TIMEOUT_MS = 5_000
const STATUSES = new Set<InvestigationStatus>([
  'pending', 'collecting', 'analyzing', 'action_planned', 'executing',
  'verifying', 'needs_review', 'failed', 'interrupted', 'closed',
])
const MODES = new Set<InvestigationMode>(['normal', 'fail_block_once'])

export class InvestigationApiError extends Error {
  readonly code: string | undefined
  readonly requestId: string | undefined
  readonly status: number | undefined

  constructor(message: string, options: { code?: string; requestId?: string; status?: number } = {}) {
    super(message)
    this.name = 'InvestigationApiError'
    this.code = options.code
    this.requestId = options.requestId
    this.status = options.status
  }
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error()
  return value as Record<string, unknown>
}

function model(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const item = record(value)
  const allowed = new Set(keys)
  if (Object.keys(item).length !== keys.length || Object.keys(item).some((key) => !allowed.has(key))) {
    throw new Error()
  }
  return item
}

function string(value: unknown): string {
  if (typeof value !== 'string') throw new Error()
  return value
}

function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error()
  return value
}

function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error()
  return value
}

function nullableString(value: unknown): string | null {
  return value === null ? null : string(value)
}

function array<T>(value: unknown, parse: (entry: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Error()
  return value.map(parse)
}

function jsonObject(value: unknown): JsonObject {
  const source = record(value)
  return Object.fromEntries(Object.entries(source).map(([key, entry]) => {
    if (Array.isArray(entry)) {
      const entries = entry.map(jsonScalar)
      return [key, entries]
    }
    return [key, jsonScalar(entry)]
  }))
}

function jsonScalar(value: unknown): JsonScalar {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  throw new Error()
}

function simulationView(value: unknown): SimulationView {
  const item = model(value, [
    'id', 'generation', 'environment', 'connection_status', 'firewall_status', 'fail_block_consumed',
  ])
  const environment = string(item.environment)
  if (environment !== 'simulation') throw new Error()
  return {
    id: string(item.id), generation: number(item.generation), environment,
    connection_status: string(item.connection_status), firewall_status: string(item.firewall_status),
    fail_block_consumed: boolean(item.fail_block_consumed),
  }
}

function incidentView(value: unknown): IncidentView {
  const item = model(value, [
    'id', 'external_id', 'simulation_instance_id', 'alert_id', 'alert_status', 'endpoint', 'username',
    'source_ip', 'remote_ip', 'remote_port', 'process_name', 'parent_process_name', 'command_summary',
    'threat_label', 'created_at',
  ])
  return {
    id: string(item.id), external_id: string(item.external_id),
    simulation_instance_id: string(item.simulation_instance_id), alert_id: string(item.alert_id),
    alert_status: string(item.alert_status), endpoint: string(item.endpoint), username: string(item.username),
    source_ip: string(item.source_ip), remote_ip: string(item.remote_ip), remote_port: number(item.remote_port),
    process_name: string(item.process_name), parent_process_name: string(item.parent_process_name),
    command_summary: string(item.command_summary), threat_label: string(item.threat_label),
    created_at: string(item.created_at),
  }
}

function runSummary(value: unknown): RunSummaryView {
  const item = model(value, ['run_id', 'status', 'mode', 'created_at', 'updated_at', 'completed_at'])
  return {
    run_id: string(item.run_id), status: string(item.status), mode: string(item.mode),
    created_at: string(item.created_at), updated_at: string(item.updated_at),
    completed_at: nullableString(item.completed_at),
  }
}

function stepView(value: unknown): InvestigationStep {
  const item = model(value, [
    'step_key', 'status', 'detail', 'error_code', 'started_at', 'completed_at',
  ])
  return {
    step_key: string(item.step_key), status: string(item.status), detail: jsonObject(item.detail),
    error_code: nullableString(item.error_code), started_at: string(item.started_at),
    completed_at: nullableString(item.completed_at),
  }
}

function evidenceView(value: unknown): EvidenceView {
  const item = model(value, [
    'id', 'evidence_type', 'source', 'observed_at', 'summary', 'raw_reference', 'integrity_sha256',
    'confidence', 'confirmed', 'payload',
  ])
  return {
    id: string(item.id), evidence_type: string(item.evidence_type), source: string(item.source),
    observed_at: string(item.observed_at), summary: string(item.summary), raw_reference: string(item.raw_reference),
    integrity_sha256: string(item.integrity_sha256), confidence: number(item.confidence),
    confirmed: boolean(item.confirmed), payload: jsonObject(item.payload),
  }
}

function assessmentView(value: unknown): AssessmentView {
  const item = model(value, [
    'conclusion', 'risk_level', 'rule_ids', 'evidence_ids', 'recommended_action', 'explanation',
  ])
  return {
    conclusion: string(item.conclusion), risk_level: string(item.risk_level),
    rule_ids: array(item.rule_ids, string), evidence_ids: array(item.evidence_ids, string),
    recommended_action: nullableString(item.recommended_action), explanation: string(item.explanation),
  }
}

function toolResultView(value: unknown): ToolResultView {
  const item = model(value, [
    'tool_name', 'target', 'idempotency_key', 'status', 'before_state', 'after_state', 'error_code',
  ])
  return {
    tool_name: string(item.tool_name), target: string(item.target), idempotency_key: string(item.idempotency_key),
    status: string(item.status), before_state: jsonObject(item.before_state), after_state: jsonObject(item.after_state),
    error_code: nullableString(item.error_code),
  }
}

function verificationView(value: unknown): VerificationView {
  const item = model(value, ['blocked', 'connection_stopped', 'observed_at', 'evidence_ids'])
  return {
    blocked: boolean(item.blocked), connection_stopped: boolean(item.connection_stopped),
    observed_at: string(item.observed_at), evidence_ids: array(item.evidence_ids, string),
  }
}

function resetResponse(value: unknown): ResetSimulationResponse {
  const item = model(value, ['simulation', 'incident'])
  return { simulation: simulationView(item.simulation), incident: incidentView(item.incident) }
}

function investigationResponse(value: unknown): InvestigationResponse {
  const item = model(value, [
    'run_id', 'incident_id', 'simulation_instance_id', 'status', 'mode', 'created_at', 'updated_at',
    'completed_at', 'simulation', 'steps', 'evidence', 'assessment', 'tool_result', 'verification',
  ])
  const status = string(item.status) as InvestigationStatus
  const mode = string(item.mode) as InvestigationMode
  if (!STATUSES.has(status) || !MODES.has(mode)) throw new Error()
  return {
    run_id: string(item.run_id), incident_id: string(item.incident_id),
    simulation_instance_id: string(item.simulation_instance_id), status, mode,
    created_at: string(item.created_at), updated_at: string(item.updated_at),
    completed_at: nullableString(item.completed_at), simulation: simulationView(item.simulation),
    steps: array(item.steps, stepView), evidence: array(item.evidence, evidenceView),
    assessment: item.assessment === null ? null : assessmentView(item.assessment),
    tool_result: item.tool_result === null ? null : toolResultView(item.tool_result),
    verification: item.verification === null ? null : verificationView(item.verification),
  }
}

function incidentResponse(value: unknown): IncidentResponse {
  const item = model(value, ['incident', 'runs'])
  return { incident: incidentView(item.incident), runs: array(item.runs, runSummary) }
}

function auditEvent(value: unknown): AuditEventView {
  const item = model(value, ['id', 'sequence', 'event_type', 'request_id', 'occurred_at', 'payload'])
  return {
    id: string(item.id), sequence: number(item.sequence), event_type: string(item.event_type),
    request_id: string(item.request_id), occurred_at: string(item.occurred_at), payload: jsonObject(item.payload),
  }
}

function auditResponse(value: unknown): AuditResponse {
  const item = model(value, ['incident_id', 'events'])
  return { incident_id: string(item.incident_id), events: array(item.events, auditEvent) }
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException('Request aborted', 'AbortError')
}

async function request<T>(path: string, parse: (value: unknown) => T, init: RequestInit, callerSignal?: AbortSignal): Promise<T> {
  if (callerSignal?.aborted) throw abortReason(callerSignal)
  const controller = new AbortController()
  const onCallerAbort = () => controller.abort(abortReason(callerSignal as AbortSignal))
  callerSignal?.addEventListener('abort', onCallerAbort, { once: true })
  const timeout = window.setTimeout(
    () => controller.abort(new DOMException('Investigation request timed out', 'TimeoutError')),
    REQUEST_TIMEOUT_MS,
  )

  try {
    const result = await fetch(`${API_ROOT}${path}`, { ...init, signal: controller.signal })
    let payload: unknown
    try {
      payload = await result.json()
    } catch {
      if (!result.ok) throw new InvestigationApiError(`Investigation request failed with status ${result.status}`, { status: result.status })
      throw new InvestigationApiError('Investigation API returned invalid JSON', { status: result.status })
    }
    if (!result.ok) {
      try {
        const body = record(payload)
        const publicError = record(body.error)
        throw new InvestigationApiError(string(publicError.message), {
          code: string(publicError.code), requestId: string(publicError.request_id), status: result.status,
        })
      } catch (error) {
        if (error instanceof InvestigationApiError) throw error
        throw new InvestigationApiError(`Investigation request failed with status ${result.status}`, { status: result.status })
      }
    }
    try {
      return parse(payload)
    } catch {
      throw new InvestigationApiError('Investigation API returned an unexpected success body', { status: result.status })
    }
  } finally {
    window.clearTimeout(timeout)
    callerSignal?.removeEventListener('abort', onCallerAbort)
  }
}

const JSON_HEADERS = { 'Content-Type': 'application/json' }

export function resetPhishingScenario(signal?: AbortSignal): Promise<ResetSimulationResponse> {
  return request('/simulations/phishing/reset', resetResponse, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, signal)
}

export function startInvestigation(simulationInstanceId: string, mode: InvestigationMode, signal?: AbortSignal): Promise<InvestigationResponse> {
  return request('/investigations', investigationResponse, {
    method: 'POST', headers: JSON_HEADERS,
    body: JSON.stringify({ simulation_instance_id: simulationInstanceId, mode }),
  }, signal)
}

export function getInvestigation(runId: string, signal?: AbortSignal): Promise<InvestigationResponse> {
  return request(`/investigations/${encodeURIComponent(runId)}`, investigationResponse, { method: 'GET' }, signal)
}

export function getIncident(incidentId: string, signal?: AbortSignal): Promise<IncidentResponse> {
  return request(`/incidents/${encodeURIComponent(incidentId)}`, incidentResponse, { method: 'GET' }, signal)
}

export function getAudit(incidentId: string, signal?: AbortSignal): Promise<AuditResponse> {
  return request(`/incidents/${encodeURIComponent(incidentId)}/audit`, auditResponse, { method: 'GET' }, signal)
}
