import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { DashboardPage } from './DashboardPage'

const RUN_ID = '11111111-1111-4111-8111-111111111111'
const INCIDENT_ID = '22222222-2222-4222-8222-222222222222'
const context = vi.hoisted((): { incidentId: string | null; runId: string | null } => ({
  incidentId: '22222222-2222-4222-8222-222222222222',
  runId: '11111111-1111-4111-8111-111111111111',
}))
const health = vi.hoisted(() => ({ getLiveness: vi.fn() }))
const investigation = vi.hoisted(() => ({ getInvestigation: vi.fn() }))

vi.mock('../../app/RunContext', () => ({ useRunContext: () => context }))
vi.mock('../../api/client', () => health)
vi.mock('../investigation/api', () => investigation)

function run() {
  return {
    run_id: RUN_ID, incident_id: INCIDENT_ID, simulation_instance_id: INCIDENT_ID,
    status: 'closed', mode: 'normal', created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:01:00Z', completed_at: '2026-07-24T00:01:00Z',
    simulation: { id: INCIDENT_ID, generation: 1, environment: 'simulation', connection_status: 'stopped', firewall_status: 'blocked', fail_block_consumed: false },
    steps: [], evidence: [
      { id: INCIDENT_ID, evidence_type: 'network', source: 'simulation', observed_at: '2026-07-24T00:00:00Z', summary: '恶意外连', raw_reference: 'safe-ref', integrity_sha256: 'a'.repeat(64), confidence: .9, confirmed: true, integrity_verified: true, payload: {} },
    ],
    assessment: { conclusion: '已确认威胁', risk_level: 'high', rule_ids: [], evidence_ids: [INCIDENT_ID], recommended_action: 'block', explanation: '证据充分' },
    tool_result: { tool_name: 'block_ip', target: '203.0.113.8', idempotency_key: 'safe-key', status: 'succeeded', before_state: {}, after_state: {}, error_code: null },
    verification: { blocked: true, connection_stopped: true, observed_at: '2026-07-24T00:01:00Z', evidence_ids: [INCIDENT_ID] },
  }
}

beforeEach(() => {
  context.incidentId = INCIDENT_ID
  context.runId = RUN_ID
  health.getLiveness.mockReset().mockResolvedValue({ status: 'ok' })
  investigation.getInvestigation.mockReset().mockResolvedValue(run())
})

describe('DashboardPage', () => {
  it('summarizes only the selected public investigation projection', async () => {
    render(<MemoryRouter><DashboardPage /></MemoryRouter>)

    expect(await screen.findByText('已确认威胁')).toBeVisible()
    expect(screen.getByText('高风险')).toBeVisible()
    expect(screen.getByText('1 条已确认')).toBeVisible()
    expect(screen.getByText('执行成功')).toBeVisible()
    expect(screen.getByText('处置已验证')).toBeVisible()
    expect(screen.getByRole('link', { name: '打开事件调查' })).toHaveAttribute('href', expect.stringContaining('/events'))
    expect(screen.queryByText(/raw_reference|integrity_sha256|before_state/)).not.toBeInTheDocument()
  })

  it('shows an actionable empty state without inventing a case', async () => {
    context.incidentId = null
    context.runId = null
    render(<MemoryRouter><DashboardPage /></MemoryRouter>)

    expect(await screen.findByText('尚未选择调查运行')).toBeVisible()
    expect(investigation.getInvestigation).not.toHaveBeenCalled()
  })

  it('fails closed and retries the selected run', async () => {
    investigation.getInvestigation.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(run())
    const user = userEvent.setup()
    render(<MemoryRouter><DashboardPage /></MemoryRouter>)

    expect(await screen.findByRole('alert')).toHaveTextContent('offline')
    await user.click(screen.getByRole('button', { name: '重试加载' }))
    expect(await screen.findByText('已确认威胁')).toBeVisible()
  })

  it('aborts both health and investigation requests on unmount', async () => {
    health.getLiveness.mockReturnValue(new Promise(() => undefined))
    investigation.getInvestigation.mockReturnValue(new Promise(() => undefined))
    const view = render(<MemoryRouter><DashboardPage /></MemoryRouter>)
    await waitFor(() => expect(investigation.getInvestigation).toHaveBeenCalledOnce())
    const healthSignal = health.getLiveness.mock.calls[0]?.[0] as AbortSignal
    const runSignal = investigation.getInvestigation.mock.calls[0]?.[1] as AbortSignal

    view.unmount()
    expect(healthSignal.aborted).toBe(true)
    expect(runSignal.aborted).toBe(true)
  })
})
