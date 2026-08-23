export type ToolCall = {
  name: string
  label: string
  status: 'succeeded' | 'empty' | 'failed'
  reason_code: 'tool_dependency_failed' | null
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
  return data as OperationsReport
}

export async function listOperationsReports(signal?: AbortSignal): Promise<OperationsReport[]> {
  const response = await fetch('/api/v1/operations/reports?limit=30', { method: 'GET', signal })
  const data = await decode(response)
  if (!response.ok || typeof data !== 'object' || data === null || Array.isArray(data)) throw apiError(data, '加载运营报告失败')
  const items = (data as Record<string, unknown>).items
  if (!Array.isArray(items)) throw new Error('运营报告服务返回了无效数据')
  return items as OperationsReport[]
}
