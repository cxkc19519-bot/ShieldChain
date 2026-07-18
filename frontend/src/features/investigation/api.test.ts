import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  getAudit,
  getIncident,
  getInvestigation,
  InvestigationApiError,
  resetPhishingScenario,
  startInvestigation,
} from './api'

const ID = '11111111-1111-4111-8111-111111111111'
const RUN_ID = '22222222-2222-4222-8222-222222222222'
const NOW = '2026-07-14T00:00:00Z'

const response = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

const simulation = {
  id: ID,
  generation: 1,
  environment: 'simulation' as const,
  connection_status: 'connected',
  firewall_status: 'open',
  fail_block_consumed: false,
}

const incident = {
  id: ID,
  external_id: 'INC-1',
  simulation_instance_id: ID,
  alert_id: 'ALERT-1',
  alert_status: 'open',
  endpoint: 'workstation-1',
  username: 'analyst',
  source_ip: '192.0.2.10',
  remote_ip: '198.51.100.24',
  remote_port: 443,
  process_name: 'powershell.exe',
  parent_process_name: 'explorer.exe',
  command_summary: 'download payload',
  threat_label: 'phishing',
  created_at: NOW,
}

const investigation = {
  run_id: RUN_ID,
  incident_id: ID,
  simulation_instance_id: ID,
  status: 'pending' as const,
  mode: 'normal' as const,
  created_at: NOW,
  updated_at: NOW,
  completed_at: null,
  simulation,
  steps: [],
  evidence: [],
  assessment: null,
  tool_result: null,
  verification: null,
}

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('investigation API client', () => {
  it('uses the exact reset and start wire contracts', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response({ simulation, incident }, { status: 201 }))
      .mockResolvedValueOnce(response(investigation, { status: 202 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(resetPhishingScenario()).resolves.toEqual({ simulation, incident })
    await expect(startInvestigation(ID, 'normal')).resolves.toEqual(investigation)

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/api/v1/simulations/phishing/reset',
      expect.objectContaining({ method: 'POST', body: '{}', signal: expect.any(AbortSignal) }),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/v1/investigations',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ simulation_instance_id: ID, mode: 'normal' }),
        signal: expect.any(AbortSignal),
      }),
    )
  })

  it('parses all three GET response contracts and preserves snake_case tool_result', async () => {
    const withResult = {
      ...investigation,
      status: 'closed',
      completed_at: NOW,
      evidence: [{
        id: ID, evidence_type: 'network_connection', source: 'simulated_edr', observed_at: NOW,
        summary: 'connection', raw_reference: 'simulation://connection/1', integrity_sha256: 'a'.repeat(64),
        confidence: 0.98, confirmed: true, integrity_verified: false,
        payload: { remote_ip: '198.51.100.24' },
      }],
      tool_result: {
        tool_name: 'simulated_firewall',
        target: '198.51.100.24:443',
        idempotency_key: 'block-1',
        status: 'blocked',
        before_state: { firewall_status: 'open' },
        after_state: { firewall_status: 'blocked' },
        error_code: null,
      },
      verification: {
        blocked: true,
        connection_stopped: true,
        observed_at: NOW,
        evidence_ids: [ID],
      },
    }
    const incidentBody = {
      incident,
      runs: [{ run_id: RUN_ID, status: 'closed', mode: 'normal', created_at: NOW, updated_at: NOW, completed_at: NOW }],
    }
    const auditBody = {
      incident_id: ID,
      events: [{ id: ID, sequence: 1, event_type: 'simulation_reset', request_id: 'req-1', occurred_at: NOW, payload: { generation: 1 } }],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce(response(withResult))
        .mockResolvedValueOnce(response(incidentBody))
        .mockResolvedValueOnce(response(auditBody)),
    )

    await expect(getInvestigation(RUN_ID)).resolves.toEqual(withResult)
    await expect(getIncident(ID)).resolves.toEqual(incidentBody)
    await expect(getAudit(ID)).resolves.toEqual(auditBody)
  })

  it.each([
    [{ ...investigation, status: 'unknown' }, 'unexpected success body'],
    [{ ...investigation, tool_result: { target: '198.51.100.24:443' } }, 'unexpected success body'],
  ])('rejects malformed success contracts', async (body, expected) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(body)))

    await expect(getInvestigation(RUN_ID)).rejects.toMatchObject({
      name: 'InvestigationApiError',
      message: expect.stringContaining(expected),
    })
  })

  it('rejects an unknown top-level response key', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ...investigation, extra: 'unexpected' })))

    await expect(getInvestigation(RUN_ID)).rejects.toMatchObject({
      name: 'InvestigationApiError',
      message: expect.stringContaining('unexpected success body'),
    })
  })

  it('rejects an unknown key in a nested response model', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({
      ...investigation,
      simulation: { ...simulation, extra: 'unexpected' },
    })))

    await expect(getInvestigation(RUN_ID)).rejects.toBeInstanceOf(InvestigationApiError)
  })

  it('allows arbitrary keys inside declared JSON value maps', async () => {
    const body = {
      ...investigation,
      steps: [{
        step_key: 'collect', status: 'completed', detail: { reviewer_defined: ['safe', 1, true, null] },
        error_code: null, started_at: NOW, completed_at: NOW,
      }],
    }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(body)))

    await expect(getInvestigation(RUN_ID)).resolves.toEqual(body)
  })

  it('rejects invalid JSON with InvestigationApiError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{', { status: 200 })))

    await expect(getInvestigation(RUN_ID)).rejects.toBeInstanceOf(InvestigationApiError)
  })

  it('surfaces only the safe public error fields', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response(
          { error: { code: 'incident_not_found', message: 'Incident not found', request_id: 'req-safe', secret: 'do-not-render' } },
          { status: 404 },
        ),
      ),
    )

    const error = await getIncident(ID).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(InvestigationApiError)
    expect(error).toMatchObject({ code: 'incident_not_found', message: 'Incident not found', requestId: 'req-safe', status: 404 })
    expect(String(error)).not.toContain('do-not-render')
  })

  it('honors caller abort and releases request resources', async () => {
    vi.useFakeTimers()
    const caller = new AbortController()
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true })
        }),
      ),
    )

    const request = getAudit(ID, caller.signal)
    caller.abort(new DOMException('Cancelled', 'AbortError'))

    await expect(request).rejects.toMatchObject({ name: 'AbortError' })
    expect(vi.getTimerCount()).toBe(0)
  })
})
