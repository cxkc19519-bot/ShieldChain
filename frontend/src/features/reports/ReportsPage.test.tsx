import { render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ReportsPage } from './ReportsPage'

const ID = '11111111-1111-4111-8111-111111111111'
const context = vi.hoisted(() => ({ incidentId: null as string | null, runId: null as string | null }))
const api = vi.hoisted(() => ({ loadReportBundle: vi.fn() }))
vi.mock('../../app/RunContext', () => ({ useRunContext: () => context }))
vi.mock('./api', () => api)

const sources = {
  incident: { status: 'available', message: '公开投影可用' },
  investigation: { status: 'available', message: '公开投影可用' },
  audit: { status: 'available', message: '公开投影可用' },
  agents: { status: 'unavailable', message: '智能体轨迹不存在' },
  tools: { status: 'available', message: '公开投影可用' },
  react: { status: 'available', message: '公开投影可用' },
} as const

const bundle = {
  sources,
  incident: { incident: { external_id: 'INC-42', threat_label: 'malware', endpoint: 'host-7', remote_ip: '203.0.113.8', remote_port: 443 }, runs: [] },
  investigation: {
    status: 'closed', updated_at: '2026-07-24T01:00:00Z',
    assessment: { conclusion: 'confirmed_malicious', risk_level: 'high', explanation: '证据链确认恶意连接。' },
    verification: { blocked: true, connection_stopped: true },
    evidence: [{ id: ID, summary: '终端连接证据', source: 'simulation', integrity_verified: true, integrity_sha256: 'sha256-public' }],
  },
  collaboration: null,
  tools: { run_id: ID, calls: [{ id: ID, status: 'succeeded', risk: 'high', tool_name: 'block_ip', target: '203.0.113.8', policy_outcome: 'allowed', approval_outcome: 'approved', verification_outcome: 'verified' }] },
  react: { status: 'completed', revision: 3, decisions: [{ id: ID, decision: 'stop', reason_code: 'goal_verified', decided_at: '2026-07-24T00:59:00Z' }] },
  audit: { incident_id: ID, events: [
    { id: 'event-2', sequence: 2, event_type: 'verification.completed', request_id: 'request-2', occurred_at: '2026-07-24T00:02:00Z', payload: { raw_prompt: 'private prompt' } },
    { id: 'event-1', sequence: 1, event_type: 'investigation.started', request_id: 'request-1', occurred_at: '2026-07-24T00:01:00Z', payload: { token: 'secret token' } },
  ] },
}

beforeEach(() => {
  context.incidentId = ID
  context.runId = ID
  api.loadReportBundle.mockReset().mockResolvedValue(bundle)
})

describe('ReportsPage', () => {
  it('renders a read-only report with ordered audit and explicit source gaps', async () => {
    render(<ReportsPage />)

    expect(await screen.findByRole('heading', { name: '调查结论' })).toBeVisible()
    expect(screen.getByText('confirmed_malicious')).toBeVisible()
    expect(screen.getByText('智能体轨迹不存在')).toBeVisible()
    const events = screen.getAllByTestId('audit-event')
    expect(within(events[0]).getByText('investigation.started')).toBeVisible()
    expect(within(events[1]).getByText('verification.completed')).toBeVisible()
    expect(screen.queryByText('private prompt')).not.toBeInTheDocument()
    expect(screen.queryByText('secret token')).not.toBeInTheDocument()
    expect(api.loadReportBundle).toHaveBeenCalledWith({ incidentId: ID, runId: ID }, expect.any(AbortSignal))
  })

  it('does not generate a report without a shared selection', () => {
    context.incidentId = null
    context.runId = null
    render(<ReportsPage />)

    expect(screen.getByText('尚未选择报告范围')).toBeVisible()
    expect(api.loadReportBundle).not.toHaveBeenCalled()
  })

  it('shows loading and aborts page-owned aggregation on unmount', async () => {
    let observed: AbortSignal | undefined
    api.loadReportBundle.mockImplementation((_selection: unknown, signal: AbortSignal) => {
      observed = signal
      return new Promise(() => undefined)
    })
    const view = render(<ReportsPage />)

    expect(screen.getByText('正在生成只读报告')).toBeVisible()
    await waitFor(() => expect(observed).toBeDefined())
    view.unmount()
    expect(observed?.aborted).toBe(true)
  })
})
