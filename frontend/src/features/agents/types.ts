export interface TrajectoryReference {
  id: string
  kind: 'evidence' | 'knowledge'
  source_id: string
  observed_at: string
  integrity_sha256: string
}

export interface RoleStatus {
  role: string
  status: string
  summary: string | null
  reason_code: string | null
  citations: TrajectoryReference[]
  updated_at: string | null
}

export interface Handoff {
  id: string
  sender: string
  receiver: string
  conclusion: string
  confidence: number
  open_questions: string[]
  recommended_actions: string[]
  citations: TrajectoryReference[]
  created_at: string
}

export interface Budget {
  step_limit: number
  steps_used: number
  loop_limit: number
  loops_used: number
  time_limit_seconds: number
  time_used_seconds: number
  token_limit: number
  tokens_used: number
  cost_limit_usd: number
  cost_used_usd: number
  tool_call_limit: number
  tool_calls_used: number
}

export interface CollaborationTrajectory {
  run_id: string
  case_id: string
  phase: string
  revision: number
  shared_summary: string
  confirmed_facts: string[]
  role_statuses: RoleStatus[]
  handoffs: Handoff[]
  citations: TrajectoryReference[]
  budget: Budget
  reason_codes: string[]
  updated_at: string
}
