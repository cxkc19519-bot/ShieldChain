export interface ToolTraceItem {
  id: string
  tool_name: string
  tool_version: string
  status: string
  reason: string | null
  target: string
  policy_outcome: string | null
  approval_outcome: string | null
  attempt_outcomes: string[]
  verification_outcome: string | null
  evidence_ids: string[]
  created_at: string
  updated_at: string
}

export interface ToolTrace {
  run_id: string
  calls: ToolTraceItem[]
}

export interface ToolMutation {
  call_id: string | null
  status: string
  revision: number
}
