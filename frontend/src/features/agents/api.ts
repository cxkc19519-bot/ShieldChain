import type { Budget, CollaborationTrajectory, Handoff, RoleStatus, TrajectoryReference } from './types'

const API_ROOT = '/api/v1'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid object')
  return value as Record<string, unknown>
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error('invalid text')
  return value
}

function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('invalid number')
  return value
}

function nullableText(value: unknown): string | null {
  return value === null ? null : text(value)
}

function array<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Error('invalid array')
  return value.map(parse)
}

function reference(value: unknown): TrajectoryReference {
  const item = record(value)
  const kind = text(item.kind)
  if (kind !== 'evidence' && kind !== 'knowledge') throw new Error('invalid reference kind')
  return {
    id: text(item.id), kind, source_id: text(item.source_id),
    observed_at: text(item.observed_at), integrity_sha256: text(item.integrity_sha256),
  }
}

function role(value: unknown): RoleStatus {
  const item = record(value)
  return {
    role: text(item.role), status: text(item.status), summary: nullableText(item.summary),
    reason_code: nullableText(item.reason_code), citations: array(item.citations, reference),
    updated_at: nullableText(item.updated_at),
  }
}

function handoff(value: unknown): Handoff {
  const item = record(value)
  return {
    id: text(item.id), sender: text(item.sender), receiver: text(item.receiver),
    conclusion: text(item.conclusion), confidence: number(item.confidence),
    open_questions: array(item.open_questions, text),
    recommended_actions: array(item.recommended_actions, text),
    citations: array(item.citations, reference), created_at: text(item.created_at),
  }
}

function budget(value: unknown): Budget {
  const item = record(value)
  return {
    step_limit: number(item.step_limit), steps_used: number(item.steps_used),
    loop_limit: number(item.loop_limit), loops_used: number(item.loops_used),
    time_limit_seconds: number(item.time_limit_seconds), time_used_seconds: number(item.time_used_seconds),
    token_limit: number(item.token_limit), tokens_used: number(item.tokens_used),
    cost_limit_usd: number(item.cost_limit_usd), cost_used_usd: number(item.cost_used_usd),
    tool_call_limit: number(item.tool_call_limit), tool_calls_used: number(item.tool_calls_used),
  }
}

function trajectory(value: unknown): CollaborationTrajectory {
  const item = record(value)
  return {
    run_id: text(item.run_id), case_id: text(item.case_id), phase: text(item.phase),
    revision: number(item.revision), shared_summary: text(item.shared_summary),
    confirmed_facts: array(item.confirmed_facts, text),
    role_statuses: array(item.role_statuses, role), handoffs: array(item.handoffs, handoff),
    citations: array(item.citations, reference), budget: budget(item.budget),
    reason_codes: array(item.reason_codes, text), updated_at: text(item.updated_at),
  }
}

export async function getCollaborationTrajectory(runId: string, signal?: AbortSignal): Promise<CollaborationTrajectory> {
  if (!UUID.test(runId)) throw new Error('请输入有效的调查运行 ID')
  const response = await fetch(`${API_ROOT}/agents/runs/${encodeURIComponent(runId)}/trajectory`, {
    method: 'GET', signal,
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new Error('智能体轨迹服务返回了无效响应')
  }
  if (!response.ok) {
    const message = (() => {
      try { return text(record(record(body).error).message) } catch { return `轨迹请求失败（${response.status}）` }
    })()
    throw new Error(message)
  }
  try { return trajectory(body) } catch { throw new Error('智能体轨迹数据不符合公开契约') }
}
