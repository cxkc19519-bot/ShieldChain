import { afterEach, describe, expect, it, vi } from 'vitest'

import { controlReactLoop, getReactTrajectory } from './reactApi'

const ID = '11111111-1111-4111-8111-111111111111'
const budget = { step_limit: 10, steps_used: 2, loop_limit: 3, loops_used: 1, time_limit_seconds: 60, time_used_seconds: 5, token_limit: 1000, tokens_used: 100, cost_limit_usd: 1, cost_used_usd: 0, tool_call_limit: 3, tool_calls_used: 1 }
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('react API', () => {
  it('parses the whitelisted public trajectory', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ loop_id: ID, run_id: ID, case_id: ID, status: 'running', revision: 2, budget, observations: [{ id: ID, iteration: 1, source: 'tool', status: 'failed', reason_code: 'timeout', citations: [], tool_call_id: null, verification_id: null, observed_at: '2026-07-24T00:00:00Z' }], assessments: [{ id: ID, observation_id: ID, category: 'transient', recoverable: true, confidence: .9, reason_code: 'retry', assessed_at: '2026-07-24T00:00:00Z' }], plan_revisions: [], decisions: [], controls: [], updated_at: '2026-07-24T00:00:00Z' })))
    const result = await getReactTrajectory(ID)
    expect(result.observations[0]?.reason_code).toBe('timeout')
    expect(result.assessments[0]?.recoverable).toBe(true)
  })

  it('submits only the operator reason for takeover', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ loop_id: ID, status: 'human_takeover', revision: 3 }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(controlReactLoop(ID, 'takeover', '人工复核')).resolves.toMatchObject({ status: 'human_takeover' })
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(JSON.parse(String(init.body))).toEqual({ reason: '人工复核' })
    expect(String(init.body)).not.toMatch(/tenant|principal|permission|budget/)
  })

  it('fails closed on malformed private-shaped data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ loop_id: ID, run_id: ID, case_id: ID, status: 'running', revision: 1, budget, observations: [{ chain_of_thought: 'secret' }], assessments: [], plan_revisions: [], decisions: [], controls: [], updated_at: 'now' })))
    await expect(getReactTrajectory(ID)).rejects.toThrow('不符合公开契约')
  })
})
