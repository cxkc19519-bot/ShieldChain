export type FindingStatus = 'new' | 'triaged' | 'remediation_approved' | 'remediation_in_progress' | 'verification_pending' | 'closed' | 'accepted_risk'

export type WorkflowEvent = {
  id: string; event_type: string; actor_type: 'scanner' | 'agent' | 'human' | 'system'
  from_status: FindingStatus | null; to_status: FindingStatus; reason_code: string
  summary: string; details: Record<string, unknown>; created_at: string
}

export type VulnerabilityFinding = {
  id: string; scanner: string; external_id: string; asset_id: string; asset_name: string
  cve_id: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  cvss_score: number | null; package_name: string | null; installed_version: string | null
  fixed_version: string | null; status: FindingStatus; first_seen_at: string; last_seen_at: string
  created_at: string; updated_at: string; latest_triage: WorkflowEvent | null; events: WorkflowEvent[]
}

export type VulnerabilityMetrics = {
  total: number; open: number; critical_open: number; awaiting_approval: number
  verification_pending: number; closed: number; accepted_risk: number
}

export type VulnerabilityDemoRun = {
  finding: VulnerabilityFinding; scenario: string; mode: 'isolated_simulation'; human_interventions: 0
  total_duration_ms: number
  tool_calls: Array<{ call_id: string; tool_name: string; status: 'succeeded' | 'failed'; duration_ms: number; summary: string }>
}

const root = '/api/v1/vulnerabilities'

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(`${root}${path}`, init)
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const error = body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>).error : null
    const message = error && typeof error === 'object' && !Array.isArray(error) ? (error as Record<string, unknown>).message : null
    throw new Error(typeof message === 'string' ? message : `漏洞闭环请求失败（${response.status}）`)
  }
  return body
}

function finding(value: unknown): VulnerabilityFinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('漏洞服务返回了无效数据')
  const item = value as Record<string, unknown>
  const required = ['id', 'scanner', 'external_id', 'asset_id', 'asset_name', 'cve_id', 'severity', 'status', 'first_seen_at', 'last_seen_at', 'created_at', 'updated_at']
  if (required.some((key) => typeof item[key] !== 'string') || !Array.isArray(item.events)) throw new Error('漏洞服务返回了无效数据')
  return item as unknown as VulnerabilityFinding
}

export async function listFindings(signal?: AbortSignal): Promise<VulnerabilityFinding[]> {
  const body = await request('/findings', { signal })
  if (!body || typeof body !== 'object' || Array.isArray(body) || !Array.isArray((body as Record<string, unknown>).items)) throw new Error('漏洞列表格式无效')
  return ((body as Record<string, unknown>).items as unknown[]).map(finding)
}

export async function loadMetrics(signal?: AbortSignal): Promise<VulnerabilityMetrics> {
  const body = await request('/metrics', { signal })
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('漏洞指标格式无效')
  return body as VulnerabilityMetrics
}

export async function deleteFinding(id: string): Promise<void> {
  await request(`/findings/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function mutateFinding(id: string, action: string, payload: Record<string, unknown>): Promise<VulnerabilityFinding> {
  const body = await request(`/findings/${encodeURIComponent(id)}/${action}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  })
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('漏洞变更结果无效')
  return finding((body as Record<string, unknown>).finding)
}

export async function runVulnerabilityDemo(): Promise<VulnerabilityDemoRun> {
  const body = await request('/demo/run', { method: 'POST' })
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('漏洞演示返回了无效数据')
  const item = body as Record<string, unknown>
  if (typeof item.scenario !== 'string' || item.mode !== 'isolated_simulation' || item.human_interventions !== 0 || typeof item.total_duration_ms !== 'number' || !Array.isArray(item.tool_calls)) {
    throw new Error('漏洞演示返回了不符合契约的数据')
  }
  return { ...item, finding: finding(item.finding) } as VulnerabilityDemoRun
}
