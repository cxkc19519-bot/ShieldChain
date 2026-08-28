export type ToolCall = {
  name: string
  label: string
  status: 'succeeded' | 'empty' | 'failed'
  reason_code: string | null
  arguments: Record<string, string | number>
  result_count: number
  summary: string
  items: string[]
}

export type ReportStage = {
  key: string
  label: string
  status: 'completed' | 'fallback'
  detail: string
}

export type AgentRoleRun = { role: string; label: string; status: 'completed' | 'fallback'; summary: string; handoff_to: string | null; iteration: number; decision_reason: string; response_plan: ResponsePlanReference | null }

export type ResponsePlanReference = {
  plan_id: string
  revision_id: string
  revision: number
  status: 'proposed' | 'needs_review' | 'completed_advisory'
  public_summary: string
  action_count: number
  generation_status: 'model_compiled' | 'deterministic_fallback'
  fallback_reason_code: string | null
  execution_status: 'not_executed'
}

export type OperationsReport = {
  id: string
  run_id: string | null
  run_status: 'completed' | 'legacy_without_run'
  generated_at: string
  start_at: string
  end_at: string
  agent_name: string
  model: string | null
  stages: ReportStage[]
  collaboration: AgentRoleRun[]
  tool_calls: ToolCall[]
  response_plan: ResponsePlanReference | null
  markdown: string
  html: string
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('运营报告响应不是对象')
  return value as Record<string, unknown>
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error('运营报告响应字段不是文本')
  return value
}

function nullableText(value: unknown): string | null {
  return value === null ? null : text(value)
}

function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isInteger(value) || typeof value !== 'number' || value < 0 || value > maximum) throw new Error('运营报告响应字段不是有效整数')
  return value
}

function dateText(value: unknown): string {
  const result = text(value)
  if (Number.isNaN(Date.parse(result))) throw new Error('运营报告响应时间无效')
  return result
}

function choice<const T extends readonly string[]>(value: unknown, allowed: T): T[number] {
  const result = text(value)
  if (!allowed.includes(result)) throw new Error('运营报告响应枚举无效')
  return result as T[number]
}

function list<T>(value: unknown, parser: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Error('运营报告响应字段不是列表')
  return value.map(parser)
}

function argumentsRecord(value: unknown): Record<string, string | number> {
  const source = record(value)
  const result: Record<string, string | number> = {}
  for (const [key, item] of Object.entries(source)) {
    if (typeof item === 'string' || (typeof item === 'number' && Number.isFinite(item))) result[key] = item
    else throw new Error('运营报告工具参数无效')
  }
  return result
}

function responsePlan(value: unknown): ResponsePlanReference {
  const item = record(value)
  return {
    plan_id: text(item.plan_id),
    revision_id: text(item.revision_id),
    revision: integer(item.revision),
    status: choice(item.status, ['proposed', 'needs_review', 'completed_advisory'] as const),
    public_summary: text(item.public_summary),
    action_count: integer(item.action_count, 8),
    generation_status: choice(item.generation_status, ['model_compiled', 'deterministic_fallback'] as const),
    fallback_reason_code: nullableText(item.fallback_reason_code),
    execution_status: choice(item.execution_status, ['not_executed'] as const),
  }
}

function nullableResponsePlan(value: unknown): ResponsePlanReference | null {
  return value === null ? null : responsePlan(value)
}

function toolCall(value: unknown): ToolCall {
  const item = record(value)
  const status = choice(item.status, ['succeeded', 'empty', 'failed'] as const)
  const reasonCode = nullableText(item.reason_code)
  const resultCount = integer(item.result_count, 50)
  const items = list(item.items, text)
  if (status === 'failed' && (reasonCode === null || resultCount !== 0 || items.length !== 0)) throw new Error('失败工具调用响应不一致')
  if (status !== 'failed' && reasonCode !== null) throw new Error('成功工具调用不能包含失败原因')
  return {
    name: text(item.name),
    label: text(item.label),
    status,
    reason_code: reasonCode,
    arguments: argumentsRecord(item.arguments),
    result_count: resultCount,
    summary: text(item.summary),
    items,
  }
}

function reportStage(value: unknown): ReportStage {
  const item = record(value)
  return {
    key: text(item.key),
    label: text(item.label),
    status: choice(item.status, ['completed', 'fallback'] as const),
    detail: text(item.detail),
  }
}

function agentRole(value: unknown): AgentRoleRun {
  const item = record(value)
  return {
    role: text(item.role),
    label: text(item.label),
    status: choice(item.status, ['completed', 'fallback'] as const),
    summary: text(item.summary),
    handoff_to: nullableText(item.handoff_to),
    iteration: integer(item.iteration),
    decision_reason: text(item.decision_reason),
    response_plan: nullableResponsePlan(item.response_plan),
  }
}

function operationsReport(value: unknown): OperationsReport {
  const item = record(value)
  const runId = nullableText(item.run_id)
  const runStatus = choice(item.run_status, ['completed', 'legacy_without_run'] as const)
  if (runStatus === 'completed' && runId === null) throw new Error('已完成报告缺少运行 ID')
  return {
    id: text(item.id),
    run_id: runId,
    run_status: runStatus,
    generated_at: dateText(item.generated_at),
    start_at: dateText(item.start_at),
    end_at: dateText(item.end_at),
    agent_name: text(item.agent_name),
    model: nullableText(item.model),
    stages: list(item.stages, reportStage),
    collaboration: list(item.collaboration, agentRole),
    tool_calls: list(item.tool_calls, toolCall),
    response_plan: nullableResponsePlan(item.response_plan),
    markdown: text(item.markdown),
    html: text(item.html),
  }
}

function apiError(payload: unknown, fallback: string): Error {
  if (typeof payload === 'object' && payload !== null && !Array.isArray(payload)) {
    const detail = (payload as Record<string, unknown>).detail
    if (typeof detail === 'string' && detail) return new Error(detail)
  }
  return new Error(fallback)
}

async function decode(response: Response): Promise<unknown> {
  try { return await response.json() } catch { return null }
}

export async function createOperationsReport(
  payload: { start_at?: string; end_at?: string },
  signal?: AbortSignal,
): Promise<OperationsReport> {
  const response = await fetch('/api/v1/operations/reports', {
    method: 'POST', signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  })
  const data = await decode(response)
  if (!response.ok) throw apiError(data, '生成安全运营报告失败')
  try { return operationsReport(data) } catch { throw new Error('运营报告服务返回了无效数据') }
}

export async function listOperationsReports(signal?: AbortSignal): Promise<OperationsReport[]> {
  const response = await fetch('/api/v1/operations/reports?limit=30', { method: 'GET', signal })
  const data = await decode(response)
  if (!response.ok || typeof data !== 'object' || data === null || Array.isArray(data)) throw apiError(data, '加载运营报告失败')
  const items = (data as Record<string, unknown>).items
  if (!Array.isArray(items)) throw new Error('运营报告服务返回了无效数据')
  try { return items.map(operationsReport) } catch { throw new Error('运营报告服务返回了无效数据') }
}
