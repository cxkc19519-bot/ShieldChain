import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { OperationsReportPage } from './OperationsReportPage'

const api = vi.hoisted(() => ({
  createOperationsReport: vi.fn(),
  listOperationsReports: vi.fn(),
}))

vi.mock('./api', () => api)

beforeEach(() => Object.values(api).forEach((mock) => mock.mockReset()))

describe('OperationsReportPage', () => {
  it('shows a failed tool as unknown instead of an empty successful query', async () => {
    api.listOperationsReports.mockResolvedValue([{
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

    render(<OperationsReportPage />)

    expect(await screen.findByText('tool_dependency_failed')).toBeVisible()
    expect(screen.getByText('调用失败 · 未取得可信结果')).toBeVisible()
    expect(screen.queryByText('无匹配记录')).not.toBeInTheDocument()
    expect(screen.queryByText('调用完成')).not.toBeInTheDocument()
    expect(screen.getByText('历史报告：无通用运行记录（legacy_without_run）')).toBeVisible()
  })

  it('shows a compiled response plan as advice and not execution', async () => {
    api.listOperationsReports.mockResolvedValue([{
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

    render(<OperationsReportPage />)

    expect(await screen.findByText('响应计划')).toBeVisible()
    expect(screen.getByText('未执行任何计划动作')).toBeVisible()
    expect(screen.getByText('计划生成不代表接受、审批、执行或验证成功。')).toBeVisible()
    expect(screen.getByText('建议人工复核当前报告线索。')).toBeVisible()
  })
})
