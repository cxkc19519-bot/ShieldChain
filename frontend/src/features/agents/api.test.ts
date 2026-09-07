import { afterEach, describe, expect, it, vi } from 'vitest'

import { getCollaborationTrajectory, listAgentRuns } from './api'

const ID = '11111111-1111-4111-8111-111111111111'
const payload = {
  run_id: ID, case_id: ID, phase: 'triage', revision: 1, shared_summary: 'Investigating',
  confirmed_facts: [], role_statuses: [], handoffs: [], citations: [], reason_codes: [],
  budget: { step_limit: 10, steps_used: 1, loop_limit: 2, loops_used: 0, time_limit_seconds: 60, time_used_seconds: 1, token_limit: 1000, tokens_used: 10, cost_limit_usd: 1, cost_used_usd: 0, tool_call_limit: 5, tool_calls_used: 0 },
  updated_at: '2026-07-23T00:00:00Z',
}

afterEach(() => vi.restoreAllMocks())

describe('agents API client', () => {
  it('lists recent investigations as selectable run summaries', async () => {
    const item = { run_id: ID, run_tracking_id: 'RUN-1111', incident_id: ID, incident_tracking_id: 'INC-1111', status: 'closed', threat_label: '钓鱼行为', endpoint: 'workstation-01', created_at: '2026-09-07T00:00:00Z', updated_at: '2026-09-07T01:00:00Z', completed_at: '2026-09-07T01:00:00Z' }
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ reports: [item] }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(listAgentRuns()).resolves.toEqual([{ run_id: ID, run_tracking_id: 'RUN-1111', incident_id: ID, incident_tracking_id: 'INC-1111', status: 'closed', threat_label: '钓鱼行为', endpoint: 'workstation-01', updated_at: '2026-09-07T01:00:00Z' }])
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/reports/history?limit=50', expect.objectContaining({ method: 'GET' }))
  })

  it('uses a read-only encoded path and sends no identity or prompt body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(getCollaborationTrajectory(ID)).resolves.toEqual(payload)
    expect(fetchMock).toHaveBeenCalledWith(`/api/v1/agents/runs/${ID}/trajectory`, expect.objectContaining({ method: 'GET' }))
    expect(fetchMock.mock.calls[0]?.[1]).not.toHaveProperty('body')
  })

  it('rejects invalid IDs and malformed public data', async () => {
    await expect(getCollaborationTrajectory('not-an-id')).rejects.toThrow('有效')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...payload, budget: {} }), { status: 200 })))
    await expect(getCollaborationTrajectory(ID)).rejects.toThrow('公开契约')
  })
})
