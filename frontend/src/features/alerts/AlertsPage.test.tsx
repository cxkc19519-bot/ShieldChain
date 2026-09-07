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
        model: 'shieldchain-qwen3-30b',
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
  it('shows agent evidence, human disposition, metrics, and a non-executing review form', async () => {
    render(<MemoryRouter><AlertsPage /></MemoryRouter>)

    expect(await screen.findByText('已确认误报')).toBeVisible()
    expect(screen.getByText('告警分诊智能体')).toBeVisible()
    expect(screen.getByText('已核对授权测试窗口和终端日志。')).toBeVisible()
    expect(screen.getByText('100.0%')).toBeVisible()
    expect(screen.getByText(/尚未写入 Wazuh/)).toBeVisible()

    fireEvent.click(screen.getByRole('button', { name: '人工定性' }))
    expect(screen.getByLabelText('人工结论')).toBeVisible()
    expect(screen.getByText(/不会删除告警或自动修改 Wazuh 规则/)).toBeVisible()
    expect(screen.getByRole('button', { name: '保存人工定性' })).toBeDisabled()
  })
})
