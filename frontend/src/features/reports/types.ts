import type { CollaborationTrajectory } from '../agents/types'
import type { ReactTrajectory } from '../agents/reactTypes'
import type { AuditResponse, IncidentResponse, InvestigationResponse } from '../investigation/types'
import type { ToolTrace } from '../tools/types'

export type ReportSourceName = 'incident' | 'investigation' | 'audit' | 'agents' | 'tools' | 'react'

export interface ReportSourceState {
  status: 'available' | 'unavailable'
  message: string
}

export interface ReportBundle {
  incident: IncidentResponse | null
  investigation: InvestigationResponse | null
  audit: AuditResponse | null
  collaboration: CollaborationTrajectory | null
  tools: ToolTrace | null
  react: ReactTrajectory | null
  sources: Record<ReportSourceName, ReportSourceState>
}
