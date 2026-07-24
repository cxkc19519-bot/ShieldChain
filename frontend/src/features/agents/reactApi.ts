import type { Budget, TrajectoryReference } from './types'
import type { ReactAction, ReactAssessment, ReactControlEvent, ReactDecision, ReactMutation, ReactObservation, ReactPlanRevision, ReactTrajectory } from './reactTypes'

const API_ROOT = '/api/v1'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function record(value: unknown): Record<string, unknown> { if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid object'); return value as Record<string, unknown> }
function text(value: unknown): string { if (typeof value !== 'string') throw new Error('invalid text'); return value }
function number(value: unknown): number { if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('invalid number'); return value }
function bool(value: unknown): boolean { if (typeof value !== 'boolean') throw new Error('invalid boolean'); return value }
function nullableText(value: unknown): string | null { return value === null ? null : text(value) }
function array<T>(value: unknown, parser: (item: unknown) => T): T[] { if (!Array.isArray(value)) throw new Error('invalid array'); return value.map(parser) }

function reference(value: unknown): TrajectoryReference {
  const item = record(value); const kind = text(item.kind)
  if (kind !== 'evidence' && kind !== 'knowledge') throw new Error('invalid reference')
  return { id: text(item.id), kind, source_id: text(item.source_id), observed_at: text(item.observed_at), integrity_sha256: text(item.integrity_sha256) }
}

function budget(value: unknown): Budget {
  const item = record(value)
  return { step_limit: number(item.step_limit), steps_used: number(item.steps_used), loop_limit: number(item.loop_limit), loops_used: number(item.loops_used), time_limit_seconds: number(item.time_limit_seconds), time_used_seconds: number(item.time_used_seconds), token_limit: number(item.token_limit), tokens_used: number(item.tokens_used), cost_limit_usd: number(item.cost_limit_usd), cost_used_usd: number(item.cost_used_usd), tool_call_limit: number(item.tool_call_limit), tool_calls_used: number(item.tool_calls_used) }
}

function observation(value: unknown): ReactObservation { const item = record(value); return { id: text(item.id), iteration: number(item.iteration), source: text(item.source), status: text(item.status), reason_code: text(item.reason_code), citations: array(item.citations, reference), tool_call_id: nullableText(item.tool_call_id), verification_id: nullableText(item.verification_id), observed_at: text(item.observed_at) } }
function assessment(value: unknown): ReactAssessment { const item = record(value); return { id: text(item.id), observation_id: text(item.observation_id), category: text(item.category), recoverable: bool(item.recoverable), confidence: number(item.confidence), reason_code: text(item.reason_code), assessed_at: text(item.assessed_at) } }
function action(value: unknown): ReactAction { const item = record(value); const expected = record(item.expected_state); for (const state of Object.values(expected)) if (!['string', 'number', 'boolean'].includes(typeof state)) throw new Error('invalid expected state'); return { id: text(item.id), action: text(item.action), target: text(item.target), expected_state: expected as Record<string, string | number | boolean>, citations: array(item.citations, reference) } }
function revision(value: unknown): ReactPlanRevision { const item = record(value); return { id: text(item.id), revision: number(item.revision), parent_revision: item.parent_revision === null ? null : number(item.parent_revision), retained_action_ids: array(item.retained_action_ids, text), removed_action_ids: array(item.removed_action_ids, text), added_actions: array(item.added_actions, action), reason: text(item.reason), created_at: text(item.created_at) } }
function decision(value: unknown): ReactDecision { const item = record(value); return { id: text(item.id), observation_id: text(item.observation_id), assessment_id: text(item.assessment_id), decision: text(item.decision), reason_code: text(item.reason_code), budget: budget(item.budget), plan_revision_id: nullableText(item.plan_revision_id), decided_at: text(item.decided_at) } }
function controlEvent(value: unknown): ReactControlEvent { const item = record(value); const control = text(item.action); if (control !== 'takeover' && control !== 'resume') throw new Error('invalid control'); return { id: text(item.id), action: control, from_status: text(item.from_status), to_status: text(item.to_status), reason_code: text(item.reason_code), revision: number(item.revision), created_at: text(item.created_at) } }

function trajectory(value: unknown): ReactTrajectory { const item = record(value); return { loop_id: text(item.loop_id), run_id: text(item.run_id), case_id: text(item.case_id), status: text(item.status), revision: number(item.revision), budget: budget(item.budget), observations: array(item.observations, observation), assessments: array(item.assessments, assessment), plan_revisions: array(item.plan_revisions, revision), decisions: array(item.decisions, decision), controls: array(item.controls, controlEvent), updated_at: text(item.updated_at) } }

async function responseBody(response: Response): Promise<unknown> { try { return await response.json() } catch { throw new Error('ReAct 服务返回了无效响应') } }
function errorMessage(body: unknown, status: number): string { try { return text(record(record(body).error).message) } catch { return `ReAct 请求失败（${status}）` } }

export async function getReactTrajectory(runId: string, signal?: AbortSignal): Promise<ReactTrajectory> {
  if (!UUID.test(runId)) throw new Error('请输入有效的调查运行 ID')
  const response = await fetch(`${API_ROOT}/react/runs/${encodeURIComponent(runId)}/trajectory`, { method: 'GET', signal })
  const body = await responseBody(response)
  if (!response.ok) throw new Error(errorMessage(body, response.status))
  try { return trajectory(body) } catch { throw new Error('ReAct 轨迹数据不符合公开契约') }
}

export async function controlReactLoop(loopId: string, control: 'takeover' | 'resume', reason: string, signal?: AbortSignal): Promise<ReactMutation> {
  if (!UUID.test(loopId)) throw new Error('ReAct 循环 ID 无效')
  const response = await fetch(`${API_ROOT}/react/loops/${encodeURIComponent(loopId)}/${control}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason }), signal })
  const body = await responseBody(response)
  if (!response.ok) throw new Error(errorMessage(body, response.status))
  try { const item = record(body); return { loop_id: text(item.loop_id), status: text(item.status), revision: number(item.revision) } } catch { throw new Error('ReAct 控制结果不符合公开契约') }
}
