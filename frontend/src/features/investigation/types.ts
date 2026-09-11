export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | JsonScalar[]
export type JsonObject = Record<string, JsonValue>

export type InvestigationStatus =
  | 'pending'
  | 'collecting'
  | 'analyzing'
  | 'action_planned'
  | 'executing'
  | 'verifying'
  | 'needs_review'
  | 'failed'
  | 'interrupted'
  | 'closed'

export type InvestigationMode = 'normal' | 'fail_block_once'

export interface SimulationView {
  id: string
  generation: number
  environment: 'simulation'
  connection_status: string
  firewall_status: string
  fail_block_consumed: boolean
}

export interface IncidentView {
  id: string
  tracking_id?: string
  external_id: string
  simulation_instance_id: string
  alert_id: string
  alert_status: string
  endpoint: string
  username: string
  source_ip: string
  remote_ip: string
  remote_port: number
  process_name: string
  parent_process_name: string
  command_summary: string
  threat_label: string
  created_at: string
}

export interface RunSummaryView {
  run_id: string
  tracking_id?: string
  status: string
  mode: string
  created_at: string
  updated_at: string
  completed_at: string | null
}

export interface InvestigationStep {
  step_key: string
  status: string
  detail: JsonObject
  error_code: string | null
  started_at: string
  completed_at: string | null
}

export interface EvidenceView {
  id: string
  evidence_type: string
  source: string
  observed_at: string
  summary: string
  raw_reference: string
  integrity_sha256: string
  confidence: number
  confirmed: boolean
  integrity_verified: boolean
  payload: JsonObject
}

export interface AssessmentView {
  conclusion: string
  risk_level: string
  rule_ids: string[]
  evidence_ids: string[]
  recommended_action: string | null
  explanation: string
}

export interface ToolResultView {
  tool_name: string
  target: string
  idempotency_key: string
  status: string
  before_state: JsonObject
  after_state: JsonObject
  error_code: string | null
}

export interface VerificationView {
  blocked: boolean
  connection_stopped: boolean
  observed_at: string
  evidence_ids: string[]
}

export interface ResetSimulationResponse {
  simulation: SimulationView
  incident: IncidentView
}

export interface InvestigationResponse {
  run_id: string
  run_tracking_id?: string
  incident_id: string
  incident_tracking_id?: string
  simulation_instance_id: string
  status: InvestigationStatus
  mode: InvestigationMode
  created_at: string
  updated_at: string
  completed_at: string | null
  simulation: SimulationView
  steps: InvestigationStep[]
  evidence: EvidenceView[]
  assessment: AssessmentView | null
  tool_result: ToolResultView | null
  verification: VerificationView | null
}

export interface IncidentResponse {
  incident: IncidentView
  runs: RunSummaryView[]
}

export interface AuditEventView {
  id: string
  sequence: number
  event_type: string
  request_id: string
  occurred_at: string
  payload: JsonObject
}

export interface AuditResponse {
  incident_id: string
  events: AuditEventView[]
}
