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

  it('supplies safe defaults for reports created before audit fields existed', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [report()] })))
    const [result] = await listOperationsReports()
    expect(result.reasoning_trace).toEqual([])
    expect(result.cross_domain).toEqual([])
    expect(result.closure.status).toBe('analysis_complete')
    expect(result.closure.action).toBe('未执行任何安全动作。')
  })

  it('preserves audit projections and response plans while stripping nested private fields', async () => {
    const plan = {
      plan_id: 'plan-1', revision_id: 'revision-1', revision: 0,
      status: 'completed_advisory', public_summary: '仅提供建议', action_count: 0,
      generation_status: 'model_compiled', fallback_reason_code: null, execution_status: 'not_executed',
    }
    const payload = {
      ...report(), response_plan: plan,
      collaboration: [{
        role: 'reporting', label: '报告智能体', status: 'completed', summary: '已完成',
        handoff_to: null, iteration: 1, decision_reason: '依据公开结果',
        response_plan: plan, evidence_domains: ['事件调查'], private_prompt: 'hidden',
      }],
      reasoning_trace: [{
        sequence: 1, phase: 'observe', title: '观测', detail: '公开证据', evidence: ['引用'],
        domains: ['事件调查'], status: 'completed', confidence: 0.7, private_prompt: 'hidden',
      }],
      cross_domain: [{
        key: 'events', label: '事件调查', source: '事件工具', result_count: 1,
        status: 'observed', summary: '已观测', raw_payload: 'hidden',
      }],
      closure: {
        status: 'analysis_complete', observed: '已观测', decision: '复核', action: '未执行',
        verification: '未验证', feedback: '补证', human_approval_required: true, credentials: 'hidden',
      },
    }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [payload] })))
    const [result] = await listOperationsReports()
    expect(result.response_plan?.plan_id).toBe('plan-1')
    expect(result.collaboration[0].response_plan?.plan_id).toBe('plan-1')
    expect(result.collaboration[0].evidence_domains).toEqual(['事件调查'])
    expect(result.reasoning_trace[0].confidence).toBe(0.7)
    expect(result.cross_domain[0].status).toBe('observed')
    expect(result.closure.human_approval_required).toBe(true)
    expect(JSON.stringify(result)).not.toContain('hidden')
  })

  it.each([
    { reasoning_trace: null },
    { reasoning_trace: [{ sequence: 1, confidence: 2 }] },
    { cross_domain: 'not-an-array' },
    { closure: { human_approval_required: 'false' } },
    { closure: null },
  ])('rejects malformed audit projections: %j', async (invalid) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [{ ...report(), ...invalid }] })))
    await expect(listOperationsReports()).rejects.toThrow('运营报告服务返回了无效数据')
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
