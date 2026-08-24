import type { ResponsePlan, ResponsePlanAction, ResponsePlanMutation, ResponsePlanRevision, ToolMutation, ToolTrace, ToolTraceItem } from './types'

const API_ROOT = '/api/v1'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('响应不是对象')
  return value as Record<string, unknown>
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error('响应字段不是文本')
  return value
}

function nullableText(value: unknown): string | null {
  return value === null ? null : text(value)
}

function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error('响应字段不是有效数字')
  return value
}

function bool(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error('响应字段不是布尔值')
  return value
}

function texts(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error('响应字段不是列表')
  return value.map(text)
}

function traceItem(value: unknown): ToolTraceItem {
  const item = record(value)
  return {
    id: text(item.id), plan_id: text(item.plan_id),
    plan_revision_id: nullableText(item.plan_revision_id), plan_action_id: nullableText(item.plan_action_id),
    tool_name: text(item.tool_name), tool_version: text(item.tool_version),
    status: text(item.status), reason: nullableText(item.reason), target: text(item.target),
    policy_outcome: nullableText(item.policy_outcome), approval_outcome: nullableText(item.approval_outcome),
    risk: nullableText(item.risk),
    attempt_outcomes: (item.attempt_outcomes as unknown[]).map(text),
    verification_outcome: nullableText(item.verification_outcome),
    evidence_ids: (item.evidence_ids as unknown[]).map(text),
    created_at: text(item.created_at), updated_at: text(item.updated_at),
  }
}

function planAction(value: unknown): ResponsePlanAction {
  const item = record(value)
  return {
    id: text(item.id), sequence: number(item.sequence), tool_name: text(item.tool_name),
    tool_version: text(item.tool_version), target_type: text(item.target_type), target: text(item.target),
    depends_on: texts(item.depends_on), evidence_ids: texts(item.evidence_ids),
    public_reason: text(item.public_reason), assessed_risk: text(item.assessed_risk),
    approval_required: bool(item.approval_required), verification_tool: nullableText(item.verification_tool),
    verification_version: nullableText(item.verification_version), rollback_strategy: text(item.rollback_strategy),
    call_id: nullableText(item.call_id), call_status: nullableText(item.call_status),
    verification_outcome: nullableText(item.verification_outcome),
  }
}

function planRevision(value: unknown): ResponsePlanRevision {
  const item = record(value)
  if (!Array.isArray(item.actions)) throw new Error('响应字段不是列表')
  return {
    id: text(item.id), revision: number(item.revision),
    parent_revision: item.parent_revision === null ? null : number(item.parent_revision),
    public_summary: text(item.public_summary), reason_code: nullableText(item.reason_code),
    actions: item.actions.map(planAction), created_at: text(item.created_at),
  }
}

function parsePlan(value: unknown): ResponsePlan {
  const item = record(value)
  if (!Array.isArray(item.revisions) || !Array.isArray(item.events)) throw new Error('响应字段不是列表')
  return {
    plan_id: text(item.plan_id), run_id: text(item.run_id), case_id: nullableText(item.case_id),
    status: text(item.status), current_revision: number(item.current_revision),
    revisions: item.revisions.map(planRevision),
    events: item.events.map((value) => { const event = record(value); return {
      id: text(event.id), revision: number(event.revision), event_type: text(event.event_type),
      reason_code: nullableText(event.reason_code), public_summary: text(event.public_summary),
      created_at: text(event.created_at),
    } }),
    created_at: text(item.created_at), updated_at: text(item.updated_at),
  }
}

function parsePlanMutation(value: unknown): ResponsePlanMutation {
  const item = record(value)
  if (!Array.isArray(item.calls)) throw new Error('响应字段不是列表')
  return {
    plan_id: text(item.plan_id), status: text(item.status), revision: number(item.revision),
    calls: item.calls.map((value) => { const call = record(value); return {
      action_id: text(call.action_id), call_id: text(call.call_id), tool_name: text(call.tool_name),
      tool_version: text(call.tool_version), status: text(call.status), request_digest: text(call.request_digest),
    } }),
  }
}

function parseTrace(value: unknown): ToolTrace {
  const item = record(value)
  if (!Array.isArray(item.calls)) throw new Error('响应字段不是列表')
  return { run_id: text(item.run_id), calls: item.calls.map(traceItem) }
}

function parseMutation(value: unknown): ToolMutation {
  const item = record(value)
  if (typeof item.revision !== 'number') throw new Error('响应修订号无效')
  return { call_id: item.call_id === null ? null : text(item.call_id), status: text(item.status), revision: item.revision }
}

async function request<T>(path: string, parse: (value: unknown) => T, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, init)
  let body: unknown
  try { body = await response.json() } catch { throw new Error('处置服务返回了无效响应') }
  if (!response.ok) {
    try { throw new Error(text(record(record(body).error).message)) } catch (error) {
      if (error instanceof Error && error.message !== '响应不是对象' && error.message !== '响应字段不是文本') throw error
      throw new Error(`处置请求失败（${response.status}）`)
    }
  }
  try { return parse(body) } catch { throw new Error('处置服务数据不符合公开契约') }
}

export function getToolTrace(runId: string, signal?: AbortSignal): Promise<ToolTrace> {
  if (!UUID.test(runId)) return Promise.reject(new Error('请输入有效的调查运行 ID'))
  return request(`/tools/runs/${encodeURIComponent(runId)}/calls`, parseTrace, { signal })
}

export function getResponsePlan(runId: string, signal?: AbortSignal): Promise<ResponsePlan> {
  if (!UUID.test(runId)) return Promise.reject(new Error('请输入有效的调查运行 ID'))
  return request(`/response-plans/runs/${encodeURIComponent(runId)}`, parsePlan, { signal })
}

export function decideResponsePlan(planId: string, action: 'accept' | 'reject', currentRevision: number, reason: string): Promise<ResponsePlanMutation> {
  return request(`/response-plans/${encodeURIComponent(planId)}/${action}`, parsePlanMutation, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_revision: currentRevision, reason }),
  })
}

function mutate(path: string, payload: object): Promise<ToolMutation> {
  return request(path, parseMutation, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
}

export function decideToolCall(callId: string, outcome: 'approved' | 'rejected', reason: string) {
  return mutate(`/tools/calls/${encodeURIComponent(callId)}/approval`, { outcome, reason })
}

export function controlToolCall(callId: string, action: 'pause' | 'resume' | 'cancel', reason: string) {
  return mutate(`/tools/calls/${encodeURIComponent(callId)}/${action}`, { reason })
}

export function setEmergencyStop(active: boolean, reason: string) {
  return mutate('/tools/emergency-stop', { active, reason })
}
