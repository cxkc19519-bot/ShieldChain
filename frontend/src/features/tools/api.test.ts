import { afterEach, describe, expect, it, vi } from 'vitest'

import { decideResponsePlan, decideToolCall, getResponsePlan, getToolTrace } from './api'

const ID = '11111111-1111-4111-8111-111111111111'
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('trusted tool API', () => {
  it('parses only the public trace contract', async () => {
    const body = { run_id: ID, calls: [{ id: ID, plan_id: ID, plan_revision_id: null, plan_action_id: null, tool_name: 'block_ip', tool_version: '1', status: 'awaiting_approval', reason: 'approval_required', target: '203.0.113.8', policy_outcome: 'approval_required', risk: 'high', approval_outcome: null, attempt_outcomes: [], verification_outcome: null, evidence_ids: [ID], created_at: '2026-07-23T00:00:00Z', updated_at: '2026-07-23T00:00:00Z' }] }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(body)))
    await expect(getToolTrace(ID)).resolves.toEqual(body)
  })

  it('sends no client authority fields in decisions', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ call_id: ID, status: 'approved', revision: 2 }))
    vi.stubGlobal('fetch', fetchMock)
    await decideToolCall(ID, 'approved', 'reviewed')
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ outcome: 'approved', reason: 'reviewed' })
  })

  it('validates the public plan projection and sends only revision plus reason', async () => {
    const plan = { plan_id: ID, run_id: ID, case_id: null, status: 'proposed', current_revision: 0, revisions: [{ id: ID, revision: 0, parent_revision: null, public_summary: 'review', reason_code: null, actions: [], created_at: '2026-08-24T00:00:00Z' }], events: [], created_at: '2026-08-24T00:00:00Z', updated_at: '2026-08-24T00:00:00Z', raw_prompt: 'private' }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(plan))
      .mockResolvedValueOnce(response({ plan_id: ID, status: 'awaiting_execution', revision: 0, calls: [] }))
    vi.stubGlobal('fetch', fetchMock)
    const parsed = await getResponsePlan(ID)
    expect(parsed).not.toHaveProperty('raw_prompt')
    expect(parsed.revisions[0].public_summary).toBe('review')
    await decideResponsePlan(ID, 'accept', 0, 'reviewed')
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ current_revision: 0, reason: 'reviewed' })
  })
})
