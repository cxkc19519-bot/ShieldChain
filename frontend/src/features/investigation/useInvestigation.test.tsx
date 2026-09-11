import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import type { InvestigationResponse } from './types'
import type { InvestigationState } from './useInvestigation'
import { useInvestigation } from './useInvestigation'

const api = vi.hoisted(() => ({
  resetPhishingScenario: vi.fn(),
  startInvestigation: vi.fn(),
  getInvestigation: vi.fn(),
  getIncident: vi.fn(),
  getAudit: vi.fn(),
}))

vi.mock('./api', () => api)

const ID = '11111111-1111-4111-8111-111111111111'
const FRESH_ID = '33333333-3333-4333-8333-333333333333'
const RUN_ID = '22222222-2222-4222-8222-222222222222'
const NOW = '2026-07-14T00:00:00Z'
const simulation = {
  id: ID, generation: 1, environment: 'simulation' as const,
  connection_status: 'connected', firewall_status: 'open', fail_block_consumed: false,
}
const incident = {
  id: ID, external_id: 'INC-1', simulation_instance_id: ID, alert_id: 'ALERT-1', alert_status: 'open',
  endpoint: 'workstation-1', username: 'analyst', source_ip: '192.0.2.10', remote_ip: '198.51.100.24',
  remote_port: 443, process_name: 'powershell.exe', parent_process_name: 'explorer.exe',
  command_summary: 'download payload', threat_label: 'phishing', created_at: NOW,
}

function run(status: InvestigationResponse['status']): InvestigationResponse {
  return {
    run_id: RUN_ID, incident_id: ID, simulation_instance_id: ID, status, mode: 'normal',
    created_at: NOW, updated_at: NOW, completed_at: status === 'failed' ? NOW : null,
    simulation, steps: [], evidence: [], assessment: null, tool_result: null, verification: null,
  }
}

let latest: InvestigationState

function Probe() {
  latest = useInvestigation()
  return (
    <div>
      <span data-testid="scenario">{latest.scenario?.simulation.id ?? 'none'}</span>
      <span data-testid="run">{latest.run?.status ?? 'none'}</span>
    </div>
  )
}

beforeEach(() => {
  vi.useFakeTimers()
  Object.values(api).forEach((mock) => mock.mockReset())
  api.resetPhishingScenario.mockResolvedValue({ simulation, incident })
  api.startInvestigation.mockResolvedValue(run('pending'))
  api.getIncident.mockResolvedValue({ incident, runs: [] })
  api.getAudit.mockResolvedValue({ incident_id: ID, events: [] })
})

afterEach(() => vi.useRealTimers())

it('reset immediately aborts an active poll and prevents its stale completion from writing', async () => {
  let resolvePoll!: (value: InvestigationResponse) => void
  let pollSignal!: AbortSignal
  api.getInvestigation.mockImplementation((_runId: string, signal: AbortSignal) => {
    pollSignal = signal
    return new Promise<InvestigationResponse>((resolve) => { resolvePoll = resolve })
  })
  render(<Probe />)
  await act(() => latest.start('normal'))
  await act(() => vi.advanceTimersByTimeAsync(500))
  expect(pollSignal.aborted).toBe(false)

  let resolveReset!: (value: unknown) => void
  api.resetPhishingScenario.mockImplementationOnce(() => new Promise((resolve) => { resolveReset = resolve }))
  let resetRequest!: Promise<void>
  act(() => {
    resetRequest = latest.reset()
    expect(pollSignal.aborted).toBe(true)
  })

  const fresh = {
    simulation: { ...simulation, id: FRESH_ID, generation: 2 },
    incident: { ...incident, id: FRESH_ID, simulation_instance_id: FRESH_ID },
  }
  await act(async () => {
    resolveReset(fresh)
    await resetRequest
  })
  await act(async () => resolvePoll(run('failed')))

  expect(screen.getByTestId('scenario')).toHaveTextContent(FRESH_ID)
  expect(screen.getByTestId('run')).toHaveTextContent('none')
  expect(vi.getTimerCount()).toBe(0)
})
