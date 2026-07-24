import { beforeEach, describe, expect, it, vi } from 'vitest'

import { loadReportBundle } from './api'

const dependencies = vi.hoisted(() => ({
  getIncident: vi.fn(), getInvestigation: vi.fn(), getAudit: vi.fn(),
  getCollaborationTrajectory: vi.fn(), getToolTrace: vi.fn(), getReactTrajectory: vi.fn(),
}))
vi.mock('../investigation/api', () => ({ getIncident: dependencies.getIncident, getInvestigation: dependencies.getInvestigation, getAudit: dependencies.getAudit }))
vi.mock('../agents/api', () => ({ getCollaborationTrajectory: dependencies.getCollaborationTrajectory }))
vi.mock('../agents/reactApi', () => ({ getReactTrajectory: dependencies.getReactTrajectory }))
vi.mock('../tools/api', () => ({ getToolTrace: dependencies.getToolTrace }))

const ID = '11111111-1111-4111-8111-111111111111'

beforeEach(() => {
  Object.values(dependencies).forEach((mock) => mock.mockReset().mockResolvedValue({ id: 'public' }))
})

describe('report bundle API', () => {
  it('keeps available public projections when one source is unavailable', async () => {
    dependencies.getCollaborationTrajectory.mockRejectedValue(new Error('智能体轨迹不存在'))

    const bundle = await loadReportBundle({ incidentId: ID, runId: ID })

    expect(bundle.incident).toEqual({ id: 'public' })
    expect(bundle.collaboration).toBeNull()
    expect(bundle.sources.agents).toEqual({ status: 'unavailable', message: '智能体轨迹不存在' })
    expect(bundle.sources.investigation.status).toBe('available')
  })

  it('does not request sources without their server identifiers', async () => {
    const bundle = await loadReportBundle({ incidentId: null, runId: null })

    expect(Object.values(dependencies).every((mock) => mock.mock.calls.length === 0)).toBe(true)
    expect(bundle.sources.audit.message).toBe('未提供事件 ID')
    expect(bundle.sources.react.message).toBe('未提供运行 ID')
  })
})
