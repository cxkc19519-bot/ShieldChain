import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { OperationsReportPage } from './OperationsReportPage'

const api = vi.hoisted(() => ({
  createOperationsReport: vi.fn(),
  listOperationsReports: vi.fn(),
}))

vi.mock('./api', () => api)

beforeEach(() => Object.values(api).forEach((mock) => mock.mockReset()))

const auditProjection = {
  reasoning_trace: [{
    sequence: 1, phase: 'observe', title: '观测：汇总安全域', detail: '保留证据缺口。',
    evidence: [], domains: [], status: 'pending', confidence: 0,
  }],
  cross_domain: [{
    key: 'endpoint_detection', label: '终端与检测', source: '告警工具',
    result_count: 0, status: 'not_observed', summary: '尚无可信观察。',
  }],
  closure: {
    status: 'analysis_complete', observed: '已记录查询结果。', decision: '人工复核。',
    action: '未执行处置。', verification: '尚未验证。', feedback: '等待新证据。',
    human_approval_required: true,
  },
}

describe('OperationsReportPage', () => {
  it('shows a failed tool as unknown instead of an empty successful query', async () => {
    api.listOperationsReports.mockResolvedValue([{
      ...auditProjection,
      id: 'OPS-20260822-FAILURE',
      run_id: null,
      run_status: 'legacy_without_run',
      generated_at: '2026-08-22T00:00:00Z',
      start_at: '2026-08-21T00:00:00Z',
      end_at: '2026-08-22T00:00:00Z',
      agent_name: '安全运营报告智能体',
      model: null,
      stages: [],
      collaboration: [],
      response_plan: null,
      tool_calls: [{
        name: 'security.alerts.list',
        label: '告警工具',
        status: 'failed',
        reason_code: 'tool_dependency_failed',
        arguments: {},
        result_count: 0,
        summary: '告警工具调用失败；未取得可信结果，需人工复核。',
        items: [],
      }],
      markdown: '# report',
      html: '<p>report</p>',
    }])

    render(<MemoryRouter><OperationsReportPage /></MemoryRouter>)

    expect(await screen.findByText('tool_dependency_failed')).toBeVisible()
    expect(screen.getByText('调用失败 · 未取得可信结果')).toBeVisible()
    expect(screen.queryByText('无匹配记录')).not.toBeInTheDocument()
    expect(screen.queryByText('调用完成')).not.toBeInTheDocument()
    expect(screen.getByText('历史报告：无通用运行记录（legacy_without_run）')).toBeVisible()
  })

  it('shows a compiled response plan as advice and not execution', async () => {
    api.listOperationsReports.mockResolvedValue([{
      ...auditProjection,
      id: 'OPS-20260823-PLAN',
      run_id: '00000000-0000-4000-8000-000000000201',
      run_status: 'completed',
      generated_at: '2026-08-23T00:00:00Z',
      start_at: '2026-08-22T00:00:00Z',
      end_at: '2026-08-23T00:00:00Z',
      agent_name: '安全运营报告智能体',
      model: 'test-model',
      stages: [],
      collaboration: [],
      response_plan: {
        plan_id: '00000000-0000-4000-8000-000000000301',
        revision_id: '00000000-0000-4000-8000-000000000302',
        revision: 0,
        status: 'completed_advisory',
        public_summary: '建议人工复核当前报告线索。',
        action_count: 0,
        generation_status: 'model_compiled',
        fallback_reason_code: null,
        execution_status: 'not_executed',
      },
      tool_calls: [],
      markdown: '# report',
      html: '<p>report</p>',
    }])

    render(<MemoryRouter><OperationsReportPage /></MemoryRouter>)

    expect(await screen.findByText('响应计划')).toBeVisible()
    expect(screen.getByRole('heading', { name: '结构化调查推理链' })).toBeVisible()
    expect(screen.getByRole('heading', { name: '跨域证据覆盖' })).toBeVisible()
    expect(screen.getByText('本轮未观测')).toBeVisible()
    expect(screen.getByText('请进入处置中心核验')).toBeVisible()
    expect(screen.getByText(/计划生成不代表接受、审批、执行或验证成功/)).toBeVisible()
    expect(screen.getByText('建议人工复核当前报告线索。')).toBeVisible()
    expect(screen.getByRole('link', { name: '进入处置中心' })).toHaveAttribute('href', '/response?run_id=00000000-0000-4000-8000-000000000201')
  })
})
