import { afterEach, describe, expect, it, vi } from 'vitest'

import { listOperationsReports } from './api'

afterEach(() => vi.unstubAllGlobals())

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function report() {
  return {
    id: 'OPS-20260824-0001',
    run_id: '00000000-0000-4000-8000-000000000001',
    run_status: 'completed',
    generated_at: '2026-08-24T00:00:00Z',
    start_at: '2026-08-23T00:00:00Z',
    end_at: '2026-08-24T00:00:00Z',
    agent_name: '安全运营报告智能体',
    model: null,
    stages: [{ key: 'report', label: '报告', status: 'completed', detail: '已完成' }],
    collaboration: [],
    tool_calls: [{
      name: 'external.peer.alerts.list', label: '外部告警', status: 'failed',
      reason_code: 'mcp_remote_timed_out', arguments: {}, result_count: 0,
      summary: '远端调用超时。', items: [],
    }],
    response_plan: null,
    markdown: '# report',
    html: '<p>report</p>',
    private_prompt: 'must not enter the render model',
  }
}

describe('operations report runtime contract', () => {
  it('rebuilds the public projection and drops extra private fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [report()] })))

    const [result] = await listOperationsReports()

    expect(result.tool_calls[0].reason_code).toBe('mcp_remote_timed_out')
    expect(result).not.toHaveProperty('private_prompt')
  })

  it('rejects malformed successful responses before rendering', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [{ ...report(), stages: null }] })))

    await expect(listOperationsReports()).rejects.toThrow('运营报告服务返回了无效数据')
  })

  it('rejects inconsistent failed tool results', async () => {
    const malformed = report()
    malformed.tool_calls[0].result_count = 1
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [malformed] })))

    await expect(listOperationsReports()).rejects.toThrow('运营报告服务返回了无效数据')
  })
})
