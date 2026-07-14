import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { InvestigationResponse, InvestigationStatus } from './types'
import { InvestigationPage } from './InvestigationPage'

const api = vi.hoisted(() => ({
  resetPhishingScenario: vi.fn(),
  startInvestigation: vi.fn(),
  getInvestigation: vi.fn(),
  getIncident: vi.fn(),
  getAudit: vi.fn(),
}))

vi.mock('./api', () => api)

const ID = '11111111-1111-4111-8111-111111111111'
const RUN_ID = '22222222-2222-4222-8222-222222222222'
const NOW = '2026-07-14T00:00:00Z'
const simulation = {
  id: ID,
  generation: 1,
  environment: 'simulation' as const,
  connection_status: 'connected',
  firewall_status: 'open',
  fail_block_consumed: false,
}
const incident = {
  id: ID, external_id: 'INC-1', simulation_instance_id: ID, alert_id: 'ALERT-1', alert_status: 'open',
  endpoint: 'workstation-1', username: 'analyst', source_ip: '192.0.2.10', remote_ip: '198.51.100.24',
  remote_port: 443, process_name: 'powershell.exe', parent_process_name: 'explorer.exe',
  command_summary: 'download payload', threat_label: 'phishing', created_at: NOW,
}

function run(status: InvestigationStatus, options: Partial<InvestigationResponse> = {}): InvestigationResponse {
  const terminal = ['closed', 'failed', 'needs_review', 'interrupted'].includes(status)
  return {
    run_id: RUN_ID,
    incident_id: ID,
    simulation_instance_id: ID,
    status,
    mode: 'normal',
    created_at: NOW,
    updated_at: NOW,
    completed_at: terminal ? NOW : null,
    simulation,
    steps: [],
    evidence: [],
    assessment: null,
    tool_result: null,
    verification: null,
    ...options,
  }
}

const reset = { simulation, incident }

beforeEach(() => {
  vi.useFakeTimers()
  Object.values(api).forEach((mock) => mock.mockReset())
  api.resetPhishingScenario.mockResolvedValue(reset)
  api.startInvestigation.mockResolvedValue(run('pending'))
  api.getIncident.mockResolvedValue({ incident, runs: [] })
  api.getAudit.mockResolvedValue({ incident_id: ID, events: [] })
})

afterEach(() => vi.useRealTimers())

async function start() {
  fireEvent.click(screen.getByRole('button', { name: '鍚姩璋冩煡' }))
  await act(async () => undefined)
}

describe('InvestigationPage', () => {
  it('runs the default simulation to a verified closed result at 500 ms intervals', async () => {
    api.getInvestigation
      .mockResolvedValueOnce(run('collecting'))
      .mockResolvedValueOnce(run('executing'))
      .mockResolvedValueOnce(run('verifying'))
      .mockResolvedValueOnce(run('closed', {
        evidence: [{ id: ID, evidence_type: 'network', source: 'simulation://network', observed_at: NOW, summary: '固定目标连接', raw_reference: 'simulation://network/1', integrity_sha256: 'a'.repeat(64), confidence: 0.99, confirmed: true, payload: { remote_ip: '198.51.100.24' } }],
        tool_result: { tool_name: 'simulated_firewall', target: '198.51.100.24:443', idempotency_key: 'block-1', status: 'blocked', before_state: { firewall_status: 'open' }, after_state: { firewall_status: 'blocked' }, error_code: null },
        verification: { blocked: true, connection_stopped: true, observed_at: NOW, evidence_ids: [ID] },
      }))
    api.getAudit.mockResolvedValue({ incident_id: ID, events: [{ id: ID, sequence: 1, event_type: 'status_changed', request_id: 'req-1', occurred_at: NOW, payload: { to_status: 'closed' } }] })
    render(<InvestigationPage />)

    expect(screen.getByText('妯℃嫙鐜')).toBeVisible()
    await start()
    expect(screen.getByRole('button', { name: '鍚姩璋冩煡' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '閲嶇疆鍦烘櫙' })).toBeDisabled()

    for (let attempt = 1; attempt <= 4; attempt += 1) {
      await act(() => vi.advanceTimersByTimeAsync(499))
      expect(api.getInvestigation).toHaveBeenCalledTimes(attempt - 1)
      await act(() => vi.advanceTimersByTimeAsync(1))
    }

    await act(async () => undefined)
    expect(screen.getByText('宸查棴鐜痐')).toBeVisible()
    expect(screen.getAllByText('198.51.100.24:443')).not.toHaveLength(0)
    expect(screen.getByText('杩炴帴宸插仠姝')).toBeVisible()
    expect(screen.getByText('瀹屾暣鎬у凡鏍￠獙')).toBeVisible()
    expect(screen.getByText('simulation://network')).toBeVisible()
    expect(screen.getByText('status_changed')).toBeVisible()
    expect(api.getIncident).toHaveBeenCalledWith(ID, expect.any(AbortSignal))
    expect(api.getAudit).toHaveBeenCalledWith(ID, expect.any(AbortSignal))
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each([
    ['failed', '澶勭疆澶辫触'],
    ['needs_review', '闇€瑕佷汉宸ュ鏍竊'],
    ['interrupted', '璋冩煡宸蹭腑鏂璥'],
  ] as const)('stops polling on %s without claiming closure', async (status, label) => {
    api.getInvestigation.mockResolvedValue(run(status))
    render(<InvestigationPage />)
    await start()

    await act(() => vi.advanceTimersByTimeAsync(500))
    await act(() => vi.advanceTimersByTimeAsync(2_000))

    expect(screen.getByText(label)).toBeVisible()
    expect(screen.queryByText('宸查棴鐜痐')).not.toBeInTheDocument()
    expect(api.getInvestigation).toHaveBeenCalledOnce()
  })

  it('does not claim closure when closed lacks both verification facts', async () => {
    api.startInvestigation.mockResolvedValue(run('closed', {
      verification: { blocked: true, connection_stopped: false, observed_at: NOW, evidence_ids: [] },
    }))
    render(<InvestigationPage />)
    await start()

    expect(screen.queryByText('宸查棴鐜痐')).not.toBeInTheDocument()
  })

  it('retries a transient polling error while preserving the truthful snapshot', async () => {
    api.getInvestigation.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(run('failed'))
    render(<InvestigationPage />)
    await start()

    await act(() => vi.advanceTimersByTimeAsync(500))
    expect(screen.getByRole('alert')).toHaveTextContent('offline')
    expect(screen.getByText('pending')).toBeVisible()
    await act(() => vi.advanceTimersByTimeAsync(500))

    expect(screen.getByText('澶勭疆澶辫触')).toBeVisible()
    expect(api.getInvestigation).toHaveBeenCalledTimes(2)
  })

  it('reset aborts page-owned polling and loads a fresh scenario', async () => {
    api.getInvestigation.mockResolvedValue(run('collecting'))
    render(<InvestigationPage />)
    await start()
    await act(() => vi.advanceTimersByTimeAsync(500))
    await act(() => vi.advanceTimersByTimeAsync(500))
    api.getInvestigation.mockResolvedValue(run('failed'))
    await act(() => vi.advanceTimersByTimeAsync(500))

    fireEvent.click(screen.getByRole('button', { name: '閲嶇疆鍦烘櫙' }))
    await act(async () => undefined)
    expect(api.resetPhishingScenario).toHaveBeenCalledTimes(2)
    expect(screen.queryByText('澶勭疆澶辫触')).not.toBeInTheDocument()
    expect(screen.getByText('妯℃嫙鐜')).toBeVisible()
  })

  it('keeps reset errors visible and does not describe them as success', async () => {
    api.resetPhishingScenario.mockRejectedValueOnce(new Error('reset unavailable'))
    render(<InvestigationPage />)
    await start()

    expect(screen.getByRole('alert')).toHaveTextContent('reset unavailable')
    expect(api.startInvestigation).not.toHaveBeenCalled()
    expect(screen.queryByText('宸查棴鐜痐')).not.toBeInTheDocument()
  })

  it('shows tool failure without a false success state', async () => {
    api.startInvestigation.mockResolvedValue(run('failed', {
      mode: 'fail_block_once',
      tool_result: { tool_name: 'simulated_firewall', target: '198.51.100.24:443', idempotency_key: 'block-1', status: 'failed', before_state: { firewall_status: 'open' }, after_state: { firewall_status: 'open' }, error_code: 'simulated_block_failure' },
    }))
    render(<InvestigationPage allowFailureMode />)
    fireEvent.change(screen.getByLabelText('璋冩煡妯″紡'), { target: { value: 'fail_block_once' } })
    await start()

    expect(screen.getByText('澶勭疆澶辫触')).toBeVisible()
    expect(screen.queryByText('宸查棴鐜痐')).not.toBeInTheDocument()
  })

  it('does not expose failure mode when production-safe mode is used', () => {
    render(<InvestigationPage allowFailureMode={false} />)

    expect(screen.queryByRole('option', { name: /fail_block_once/ })).not.toBeInTheDocument()
    expect(screen.getByLabelText('璋冩煡妯″紡')).toHaveValue('normal')
  })

  it('aborts an in-flight polling request and clears timers on unmount', async () => {
    api.getInvestigation.mockImplementation((_id: string, signal: AbortSignal) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true })
    }))
    const view = render(<InvestigationPage />)
    await start()
    await act(() => vi.advanceTimersByTimeAsync(500))
    const signal = api.getInvestigation.mock.calls[0]?.[1] as AbortSignal

    view.unmount()

    expect(signal.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
})
