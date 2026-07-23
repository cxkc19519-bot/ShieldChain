import type { ToolMutation, ToolTrace, ToolTraceItem } from './types'

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

function traceItem(value: unknown): ToolTraceItem {
  const item = record(value)
  return {
    id: text(item.id), tool_name: text(item.tool_name), tool_version: text(item.tool_version),
    status: text(item.status), reason: nullableText(item.reason), target: text(item.target),
    policy_outcome: nullableText(item.policy_outcome), approval_outcome: nullableText(item.approval_outcome),
    attempt_outcomes: (item.attempt_outcomes as unknown[]).map(text),
    verification_outcome: nullableText(item.verification_outcome),
    evidence_ids: (item.evidence_ids as unknown[]).map(text),
    created_at: text(item.created_at), updated_at: text(item.updated_at),
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
