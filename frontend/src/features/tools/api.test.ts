import { afterEach, describe, expect, it, vi } from 'vitest'

import { decideToolCall, getToolTrace } from './api'

const ID = '11111111-1111-4111-8111-111111111111'
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('trusted tool API', () => {
  it('parses only the public trace contract', async () => {
    const body = { run_id: ID, calls: [{ id: ID, tool_name: 'block_ip', tool_version: '1', status: 'awaiting_approval', reason: 'approval_required', target: '203.0.113.8', policy_outcome: 'approval_required', approval_outcome: null, attempt_outcomes: [], verification_outcome: null, evidence_ids: [ID], created_at: '2026-07-23T00:00:00Z', updated_at: '2026-07-23T00:00:00Z' }] }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(body)))
    await expect(getToolTrace(ID)).resolves.toEqual(body)
  })

  it('sends no client authority fields in decisions', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ call_id: ID, status: 'approved', revision: 2 }))
    vi.stubGlobal('fetch', fetchMock)
    await decideToolCall(ID, 'approved', 'reviewed')
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ outcome: 'approved', reason: 'reviewed' })
  })
})
