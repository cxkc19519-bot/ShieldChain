export interface ToolTraceItem {
  id: string
  plan_id: string
  plan_revision_id: string | null
  plan_action_id: string | null
  tool_name: string
  tool_version: string
  status: string
  reason: string | null
  target: string
  policy_outcome: string | null
  risk: string | null
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

export interface ResponsePlanAction {
  id: string
  sequence: number
  tool_name: string
  tool_version: string
  target_type: string
  target: string
  depends_on: string[]
  evidence_ids: string[]
  public_reason: string
  assessed_risk: string
  approval_required: boolean
  verification_tool: string | null
  verification_version: string | null
  rollback_strategy: string
  call_id: string | null
  call_status: string | null
  verification_outcome: string | null
}

export interface ResponsePlanRevision {
  id: string
  revision: number
  parent_revision: number | null
  public_summary: string
  reason_code: string | null
  actions: ResponsePlanAction[]
  created_at: string
}

export interface ResponsePlanEvent {
  id: string
  revision: number
  event_type: string
  reason_code: string | null
  public_summary: string
  created_at: string
}

export interface ResponsePlan {
  plan_id: string
  run_id: string
  case_id: string | null
  status: string
  current_revision: number
  revisions: ResponsePlanRevision[]
  events: ResponsePlanEvent[]
  created_at: string
  updated_at: string
}

export interface ResponsePlanMutation {
  plan_id: string
  status: string
  revision: number
  calls: Array<{ action_id: string; call_id: string; tool_name: string; tool_version: string; status: string; request_digest: string }>
}
