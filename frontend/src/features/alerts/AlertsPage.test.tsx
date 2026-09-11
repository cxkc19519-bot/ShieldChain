import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AlertsPage } from './AlertsPage'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/false-positive-metrics')) {
      return Promise.resolve(new Response(JSON.stringify({
        reviewed_cases: 1,
        false_positives: 1,
        true_positives: 0,
        needs_more_evidence: 0,
        false_positive_rate: 1,
        proposed_suppressions: 1,
        active_suppressions: 0,
        suppressed_alerts: 0,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    }
    return Promise.resolve(new Response(JSON.stringify({ items: [{
      id: '00000000-0000-4000-8000-000000000011',
      tracking_id: 'WAZ-2026-0001',
      alert_id: '00000000-0000-4000-8000-000000000012',
      source: 'wazuh',
      status: 'investigated',
      run_id: '00000000-0000-4000-8000-000000000013',
      severity: 12,
      rule_id: '100201',
      title: 'Suspicious PowerShell network connection',
      endpoint: 'PC-023',
      created_at: '2026-09-07T01:00:00Z',
      updated_at: '2026-09-07T02:00:00Z',
      triage_assessment: {
        run_id: '00000000-0000-4000-8000-000000000013',
        agent_name: '告警分诊智能体',
        model: 'deepseek-test',
        summary: '已关联告警与事件证据，建议核对授权测试窗口。',
        decision_reason: '优先复核高等级告警。',
        limitation: '智能体输出是研判建议，不是误报结论；最终定性必须由分析员确认。',
      },
      disposition: {
        id: '00000000-0000-4000-8000-000000000014',
        case_id: '00000000-0000-4000-8000-000000000011',
        run_id: '00000000-0000-4000-8000-000000000013',
        decision: 'false_positive',
        reason_code: 'authorized_test',
        rationale: '已核对授权测试窗口和终端日志。',
        suppression_scope: 'same_rule_endpoint',
        suppression_status: 'proposed_only',
        suppression_expires_at: '2026-09-14T02:00:00Z',
        reviewer_id: '00000000-0000-4000-8000-000000000015',
        created_at: '2026-09-07T02:00:00Z',
      },
    }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  })
})

afterEach(() => vi.unstubAllGlobals())

describe('AlertsPage false-positive governance', () => {
  it('starts a random replay when the control button is clicked', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/demo-replay/start')) return Promise.resolve(new Response(JSON.stringify({ state: 'running', sample: { id: 'sample-1', title: '测试样本' }, run_id: null }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      if (url.endsWith('/false-positive-metrics')) return Promise.resolve(new Response(JSON.stringify({ reviewed_cases: 0, false_positives: 0, true_positives: 0, needs_more_evidence: 0, false_positive_rate: null, proposed_suppressions: 0, active_suppressions: 0, suppressed_alerts: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      return Promise.resolve(new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    })
    render(<MemoryRouter><AlertsPage /></MemoryRouter>)

    fireEvent.click(screen.getByRole('button', { name: '启动随机回放' }))

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/nta/demo-replay/start', { method: 'POST' }))
    expect(await screen.findByText('正在回放')).toBeVisible()
    expect(screen.queryByText(/测试样本/)).not.toBeInTheDocument()
  })

  it('shows agent evidence, human disposition, metrics, and an approval step', async () => {
    render(<MemoryRouter><AlertsPage /></MemoryRouter>)

    expect(await screen.findByText('已确认误报')).toBeVisible()
    expect(screen.getByText('告警分诊智能体')).toBeVisible()
    expect(screen.getByText('已核对授权测试窗口和终端日志。')).toBeVisible()
    expect(screen.getByText('100.0%')).toBeVisible()
    expect(screen.getByText(/等待人工审批/)).toBeVisible()
    expect(screen.getByRole('button', { name: '批准并启用抑制' })).toBeVisible()
    expect(screen.getByRole('heading', { name: '流量回放控制' })).toBeVisible()
    expect(screen.getByRole('button', { name: '启动随机回放' })).toBeVisible()
    expect(screen.getByLabelText('自动化安全运营流程')).toHaveTextContent('1流量回放2产生告警3自动调查4自动处置5生成报告')
    expect(screen.getByRole('heading', { name: '告警列表' })).toBeVisible()

    fireEvent.click(screen.getByRole('button', { name: '人工定性' }))
    expect(screen.getByLabelText('人工结论')).toBeVisible()
    expect(screen.getByText('保存后记录人工结论和抑制建议。')).toBeVisible()
    const saveButton = screen.getByRole('button', { name: '保存人工定性' })
    expect(saveButton).toBeDisabled()
    fireEvent.change(screen.getByLabelText('复核依据'), { target: { value: '哈哈' } })
    expect(saveButton).toBeEnabled()
  })

  it('shows automatic investigation progress instead of a manual start button', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/false-positive-metrics')) return Promise.resolve(new Response(JSON.stringify({ reviewed_cases: 0, false_positives: 0, true_positives: 0, needs_more_evidence: 0, false_positive_rate: null, proposed_suppressions: 0, active_suppressions: 0, suppressed_alerts: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      return Promise.resolve(new Response(JSON.stringify({ items: [{
        id: '00000000-0000-4000-8000-000000000011', tracking_id: 'WAZ-2026-0002', alert_id: '00000000-0000-4000-8000-000000000012', source: 'wazuh', status: 'investigating', run_id: '00000000-0000-4000-8000-000000000013',
        severity: 12, rule_id: '9000085', title: '自动调查告警', endpoint: 'nta-replay', created_at: '2026-09-07T01:00:00Z', updated_at: '2026-09-07T01:00:00Z', triage_assessment: null, disposition: null,
      }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    })
    render(<MemoryRouter><AlertsPage /></MemoryRouter>)

    expect(await screen.findByText('智能体自动调查中…')).toBeVisible()
    expect(screen.queryByRole('button', { name: '启动智能体调查' })).not.toBeInTheDocument()
    expect(screen.getByText(/页面会在调查完成后更新/)).toBeVisible()
    expect(screen.getByRole('button', { name: '删除告警' })).toBeDisabled()
  })

  it('deletes a completed alert after confirmation', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<MemoryRouter><AlertsPage /></MemoryRouter>)

    fireEvent.click(await screen.findByRole('button', { name: '删除告警' }))

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/integrations/wazuh/cases/00000000-0000-4000-8000-000000000011',
      { method: 'DELETE' },
    ))
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('HTML、Markdown 和元数据文件也会一并删除'))
  })

  it('labels an abandoned investigation as terminated and allows deletion', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/false-positive-metrics')) return Promise.resolve(new Response(JSON.stringify({ reviewed_cases: 0, false_positives: 0, true_positives: 0, needs_more_evidence: 0, false_positive_rate: null, proposed_suppressions: 0, active_suppressions: 0, suppressed_alerts: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      return Promise.resolve(new Response(JSON.stringify({ items: [{
        id: '00000000-0000-4000-8000-000000000011', tracking_id: 'WAZ-2026-0005', alert_id: '00000000-0000-4000-8000-000000000012', source: 'wazuh', status: 'investigation_failed', run_id: '00000000-0000-4000-8000-000000000013',
        severity: 14, rule_id: 'SC-E2E', title: '历史任务', endpoint: 'controlled-verifier', created_at: '2026-09-05T01:00:00Z', updated_at: '2026-09-05T01:00:00Z', triage_assessment: null, disposition: null,
      }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    })
    render(<MemoryRouter><AlertsPage /></MemoryRouter>)

    expect(await screen.findByText('调查已终止')).toBeVisible()
    expect(screen.getByText(/并未继续占用模型/)).toBeVisible()
    expect(screen.getByRole('button', { name: '删除告警' })).toBeEnabled()
  })
})
