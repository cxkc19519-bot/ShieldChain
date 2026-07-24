import type { Budget, TrajectoryReference } from './types'

export interface ReactObservation {
  id: string
  iteration: number
  source: string
  status: string
  reason_code: string
  citations: TrajectoryReference[]
  tool_call_id: string | null
  verification_id: string | null
  observed_at: string
}

export interface ReactAssessment {
  id: string
  observation_id: string
  category: string
  recoverable: boolean
  confidence: number
  reason_code: string
  assessed_at: string
}

export interface ReactAction {
  id: string
  action: string
  target: string
  expected_state: Record<string, string | number | boolean>
  citations: TrajectoryReference[]
}

export interface ReactPlanRevision {
  id: string
  revision: number
  parent_revision: number | null
  retained_action_ids: string[]
  removed_action_ids: string[]
  added_actions: ReactAction[]
  reason: string
  created_at: string
}

export interface ReactDecision {
  id: string
  observation_id: string
  assessment_id: string
  decision: string
  reason_code: string
  budget: Budget
  plan_revision_id: string | null
  decided_at: string
}

export interface ReactControlEvent {
  id: string
  action: 'takeover' | 'resume'
  from_status: string
  to_status: string
  reason_code: string
  revision: number
  created_at: string
}

export interface ReactTrajectory {
  loop_id: string
  run_id: string
  case_id: string
  status: string
  revision: number
  budget: Budget
  observations: ReactObservation[]
  assessments: ReactAssessment[]
  plan_revisions: ReactPlanRevision[]
  decisions: ReactDecision[]
  controls: ReactControlEvent[]
  updated_at: string
}

export interface ReactMutation {
  loop_id: string
  status: string
  revision: number
}
