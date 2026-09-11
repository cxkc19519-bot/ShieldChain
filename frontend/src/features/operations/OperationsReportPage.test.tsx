import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { OperationsReportPage } from './OperationsReportPage'

const api = vi.hoisted(() => ({ deleteOperationsReport: vi.fn(), listOperationsReports: vi.fn() }))
vi.mock('./api', () => api)

beforeEach(() => {
  api.listOperationsReports.mockReset()
  api.deleteOperationsReport.mockReset().mockResolvedValue(undefined)
})

function report(overrides: Record<string, unknown> = {}) {
  return {
    id: 'OPS-20260908-ZERO', run_id: '00000000-0000-4000-8000-000000000211', run_status: 'completed',
    generated_at: '2026-09-08T05:00:00Z', start_at: '2026-09-08T04:00:00Z', end_at: '2026-09-08T05:00:00Z',
    agent_name: '安全运营报告智能体', model: 'test-model', stages: [], collaboration: [], tool_calls: [],
    reasoning_trace: [], cross_domain: [{ key: 'network', label: '网络', source: 'NTA', result_count: 1, status: 'observed', summary: '已观测' }],
    closure: { status: 'closed', observed: '已完成隔离回放攻击调查。', decision: '自动处置。', action: '已执行。', verification: '已验证。', feedback: '已闭环。', human_approval_required: false },
    response_plan: { plan_id: 'plan-1', revision_id: 'revision-1', revision: 0, status: 'completed', public_summary: '零人工完成。', action_count: 2, generation_status: 'model_compiled', fallback_reason_code: null, execution_status: 'verified_completed' },
    response_audit: { mode: 'zero_touch_isolated_replay', plan_id: 'plan-1', run_id: '00000000-0000-4000-8000-000000000211', loop_id: 'loop-1', policy_result: '隔离回放白名单自动授权', loop_status: 'completed', reason_code: 'completed', human_interventions: 0, actions: [], replans: [] },
    markdown: '# report', html: '<p>report</p>', ...overrides,
  }
}

describe('OperationsReportPage', () => {
  it('keeps the report page compact when no reports exist', async () => {
    api.listOperationsReports.mockResolvedValue([])
    render(<OperationsReportPage />)

    expect(await screen.findByText('尚无安全运营报告')).toBeVisible()
    expect(screen.queryByLabelText('开始时间')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '生成运营报告' })).not.toBeInTheDocument()
  })

  it('renders each report as one summary card with a standalone HTML link', async () => {
    api.listOperationsReports.mockResolvedValue([report()])
    render(<OperationsReportPage />)

    expect(await screen.findByText('OPS-20260908-ZERO')).toBeVisible()
    expect(screen.getByText('零人工闭环')).toBeVisible()
    expect(screen.getByText('2 项')).toBeVisible()
    expect(screen.getByText('1/1 域')).toBeVisible()
    expect(screen.getByText('0 次')).toBeVisible()
    expect(screen.getByRole('link', { name: '打开 HTML 报告' })).toHaveAttribute('href', '/api/v1/operations/reports/OPS-20260908-ZERO/view')
    expect(screen.getByRole('link', { name: '打开 HTML 报告' })).toHaveAttribute('target', '_blank')
    expect(screen.getByRole('link', { name: '下载 HTML' })).toHaveAttribute('href', '/api/v1/operations/reports/OPS-20260908-ZERO/view?download=true')
  })

  it('does not claim zero-touch completion for a report awaiting exceptional takeover', async () => {
    api.listOperationsReports.mockResolvedValue([report({
      id: 'OPS-NEEDS-REVIEW', response_audit: null,
      closure: { status: 'awaiting_approval', observed: '证据不足。', decision: '停止自动执行。', action: '未执行。', verification: '未验证。', feedback: '等待补证。', human_approval_required: true },
      response_plan: null,
    })])
    render(<OperationsReportPage />)

    expect(await screen.findByText('异常待接管')).toBeVisible()
    expect(screen.getByText('受控调查')).toBeVisible()
    expect(screen.getByText('需要')).toBeVisible()
    expect(screen.queryByText('零人工闭环')).not.toBeInTheDocument()
  })

  it('opens the public structured reasoning timeline from a report card', async () => {
    api.listOperationsReports.mockResolvedValue([report({
      closure: { status: 'closed', observed: '已完成调查。', decision: '检测到反向 Shell 异常通信，源地址 198.51.100.107 向目标 192.168.100.200:80 发起请求，触发规则 suricata:9000090；该事件属于隔离回放。', action: '已执行。', verification: '已验证。', feedback: '已闭环。', human_approval_required: false },
      tool_calls: [{ name: 'security.alerts.list', label: '告警 MCP', status: 'succeeded', reason_code: null, arguments: {}, result_count: 1, summary: '发现一条告警。', items: ['等级 12｜规则 suricata:9000090｜NTA 隔离回放：Struts2 反弹 Shell｜网络 198.51.100.107 → 192.168.100.200:80'] }],
      reasoning_trace: [{ sequence: 1, phase: 'observe', title: '观测网络异常', detail: 'NTA 告警达到调查阈值。', evidence: ['wazuh:alert-1'], domains: ['网络流量'], status: 'completed', confidence: .92 }],
    })])
    render(<OperationsReportPage />)

    fireEvent.click(await screen.findByRole('button', { name: '查看思维链' }))

    expect(screen.getByRole('dialog', { name: '结构化调查思维链' })).toBeVisible()
    expect(screen.getByRole('list', { name: '动态攻击调查链' })).toBeVisible()
    expect(screen.getByText('网络告警')).toBeVisible()
    expect(screen.getByText('研判结论')).toBeVisible()
    expect(screen.getByText('响应建议')).toBeVisible()
    expect(screen.queryByText('终端关联')).not.toBeInTheDocument()
    expect(screen.queryByText('身份关联')).not.toBeInTheDocument()
    expect(screen.getByText(/198\.51\.100\.107 → 192\.168\.100\.200:80 · suricata:9000090/)).toBeVisible()
    expect(screen.getAllByText(/Struts2 反弹 Shell/)).toHaveLength(2)
    expect(screen.getByText('观测网络异常')).toBeVisible()
    expect(screen.getByText('NTA 告警达到调查阈值。')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '关闭思维链' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('adds only observed domains, audited actions, replanning and verification to the dynamic chain', async () => {
    api.listOperationsReports.mockResolvedValue([report({
      closure: { status: 'closed', observed: '已完成调查。', decision: '身份异常已确认，需要停用账号。', action: '已执行。', verification: '账号状态验证通过。', feedback: '已闭环。', human_approval_required: false },
      cross_domain: [{ key: 'identity', label: '身份认证', source: 'IAM', result_count: 1, status: 'observed', summary: '发现账号 svc-risk 存在异常登录。' }],
      response_audit: { mode: 'zero_touch_isolated_replay', plan_id: 'plan-1', run_id: '00000000-0000-4000-8000-000000000211', loop_id: 'loop-1', policy_result: '已授权', loop_status: 'completed', reason_code: 'completed', human_interventions: 0,
        actions: [{ action_id: 'action-1', call_id: 'call-1', sequence: 1, tool_name: 'disable_account', tool_version: '1', target_type: 'account', target: 'svc-risk', assessed_risk: 'high', authorization: 'allow', execution_status: 'succeeded', attempt_outcomes: ['succeeded'], verification_outcome: 'verified', evidence_ids: ['evidence-1'], updated_at: '2026-09-08T05:00:00Z' }],
        replans: [{ revision: 1, event_type: 'replan', reason_code: 'new_evidence', summary: '根据新增身份日志重新规划。', created_at: '2026-09-08T05:00:00Z' }] },
    })])
    render(<OperationsReportPage />)
    fireEvent.click(await screen.findByRole('button', { name: '查看思维链' }))

    expect(screen.getByText('身份关联')).toBeVisible()
    expect(screen.getByText('停用账号')).toBeVisible()
    expect(screen.getByText('反馈重规划')).toBeVisible()
    expect(screen.getByText('结果验证')).toBeVisible()
    expect(screen.queryByText('网络告警')).not.toBeInTheDocument()
    expect(screen.queryByText('终端关联')).not.toBeInTheDocument()
  })

  it('deletes the server report after explicit confirmation', async () => {
    api.listOperationsReports.mockResolvedValue([report()])
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<OperationsReportPage />)

    fireEvent.click(await screen.findByRole('button', { name: '删除报告' }))

    await waitFor(() => expect(api.deleteOperationsReport).toHaveBeenCalledWith('OPS-20260908-ZERO'))
    expect(screen.queryByText('OPS-20260908-ZERO')).not.toBeInTheDocument()
  })
})
