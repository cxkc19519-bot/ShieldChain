import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { VulnerabilitiesPage } from './VulnerabilitiesPage'

const finding = {
  id: '00000000-0000-4000-8000-000000000101', scanner: 'OpenVAS', external_id: 'finding-1',
  asset_id: 'asset-1', asset_name: 'server-01', cve_id: 'CVE-2026-12345', severity: 'critical',
  cvss_score: 9.8, package_name: 'example-server', installed_version: '1.0.0', fixed_version: '1.0.1',
  status: 'triaged', first_seen_at: '2026-09-07T09:00:00Z', last_seen_at: '2026-09-07T09:00:00Z',
  created_at: '2026-09-07T09:00:00Z', updated_at: '2026-09-07T09:01:00Z',
  latest_triage: {
    id: '00000000-0000-4000-8000-000000000102', event_type: 'agent_triage_completed', actor_type: 'agent',
    from_status: 'new', to_status: 'triaged', reason_code: 'model_assessment',
    summary: '扫描发现需要结合资产版本和业务暴露面进一步确认。',
    details: { agent_status: 'completed', model: 'deepseek-test', priority: 'P0',
      affected_assessment: '当前资产版本可能位于受影响范围，仍需核对厂商公告。',
      remediation: '建议在批准的维护窗口升级到修复版本。', verification: '使用同一扫描器复测并保留扫描任务证据。' },
    created_at: '2026-09-07T09:01:00Z',
  },
  events: [],
}

describe('VulnerabilitiesPage', () => {
  beforeEach(() => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/metrics')) return Promise.resolve(new Response(JSON.stringify({ total: 1, open: 1, critical_open: 1, awaiting_approval: 1, verification_pending: 0, closed: 0, accepted_risk: 0 })))
      if (init?.method === 'DELETE') return Promise.resolve(new Response(null, { status: 204 }))
      if (init?.method === 'POST') return Promise.resolve(new Response(JSON.stringify({ finding: { ...finding, status: 'remediation_approved' }, event: {} }), { status: 201 }))
      return Promise.resolve(new Response(JSON.stringify({ items: [finding] })))
    }))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('deletes a finding and its workflow after confirmation', async () => {
    const fetchMock = vi.mocked(fetch)
    render(<VulnerabilitiesPage />)

    fireEvent.click(await screen.findByRole('button', { name: '展开详情' }))
    fireEvent.click(screen.getByRole('button', { name: '删除记录' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`/findings/${finding.id}`),
      expect.objectContaining({ method: 'DELETE' }),
    ))
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('全部闭环审计事件'))
  })

  it('shows model evidence and requires human rationale before approval', async () => {
    render(<VulnerabilitiesPage />)
    expect(await screen.findByText('CVE-2026-12345')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '展开详情' }))
    expect(screen.getByText(/deepseek-test/)).toBeVisible()
    const approve = screen.getByRole('button', { name: /批准修复/ })
    expect(approve).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/至少 10 个字符/), { target: { value: '已核对厂商公告和资产版本，确认需要修复。' } })
    expect(approve).toBeEnabled()
    fireEvent.click(approve)
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/decision'), expect.objectContaining({ method: 'POST' })))
  })

  it('starts the isolated zero-touch vulnerability demo from the page', async () => {
    const fetchMock = vi.mocked(fetch)
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/demo/run')) return Promise.resolve(new Response(JSON.stringify({
        finding: { ...finding, status: 'closed', installed_version: finding.fixed_version },
        scenario: 'component_upgrade', mode: 'isolated_simulation', human_interventions: 0, total_duration_ms: 321,
        tool_calls: [
          { call_id: finding.id, tool_name: 'demo.patch.apply@1', status: 'succeeded', duration_ms: 12, summary: '修复成功' },
          { call_id: finding.id, tool_name: 'demo.scanner.retest@1', status: 'succeeded', duration_ms: 9, summary: '复测通过' },
        ],
      }), { status: 201 }))
      if (url.endsWith('/metrics')) return Promise.resolve(new Response(JSON.stringify({ total: 1, open: 1, critical_open: 1, awaiting_approval: 1, verification_pending: 0, closed: 0, accepted_risk: 0 })))
      return Promise.resolve(new Response(JSON.stringify({ items: [finding] })))
    })
    render(<VulnerabilitiesPage />)
    fireEvent.click(await screen.findByRole('button', { name: '导入演示漏洞' }))
    expect(await screen.findByText(/已完成零人工漏洞闭环/)).toBeVisible()
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/demo/run'), expect.objectContaining({ method: 'POST' }))
  })

  it('shows an auditable agent workflow without hidden reasoning text', async () => {
    const workflowFinding = {
      ...finding,
      status: 'closed',
      events: [
        { id: 'event-1', event_type: 'finding_ingested', actor_type: 'scanner', from_status: null, to_status: 'new', reason_code: 'scanner_observation', summary: '扫描器发现漏洞。', details: {}, created_at: '2026-09-07T09:00:00Z' },
        finding.latest_triage,
        { id: 'event-3', event_type: 'demo_policy_authorized', actor_type: 'system', from_status: 'triaged', to_status: 'remediation_approved', reason_code: 'isolated_demo_policy_matched', summary: '策略检查通过并自动授权组件升级。', details: {}, created_at: '2026-09-07T09:02:00Z' },
        { id: 'event-4', event_type: 'demo_remediation_succeeded', actor_type: 'system', from_status: 'remediation_in_progress', to_status: 'verification_pending', reason_code: 'simulated_patch_applied', summary: '升级工具执行成功。', details: { tool_name: 'demo.patch.apply@1', duration_ms: 12 }, created_at: '2026-09-07T09:03:00Z' },
        { id: 'event-5', event_type: 'demo_verification_failed', actor_type: 'system', from_status: 'verification_pending', to_status: 'triaged', reason_code: 'simulated_scanner_retest_failed', summary: '首次复测仍发现风险。', details: { tool_name: 'demo.scanner.retest@1', duration_ms: 9, attempt: 1 }, created_at: '2026-09-07T09:04:00Z' },
        { id: 'event-6', event_type: 'demo_replan_authorized', actor_type: 'agent', from_status: 'triaged', to_status: 'remediation_approved', reason_code: 'retest_feedback_replanned', summary: '智能体根据失败反馈追加服务重启。', details: { new_tool: 'demo.service.restart@1' }, created_at: '2026-09-07T09:05:00Z' },
        { id: 'event-7', event_type: 'demo_remediation_succeeded', actor_type: 'system', from_status: 'remediation_in_progress', to_status: 'verification_pending', reason_code: 'simulated_restart_completed', summary: '追加工具执行成功。', details: { tool_name: 'demo.service.restart@1', duration_ms: 7 }, created_at: '2026-09-07T09:06:00Z' },
        { id: 'event-8', event_type: 'demo_verification_passed', actor_type: 'system', from_status: 'verification_pending', to_status: 'closed', reason_code: 'simulated_scanner_retest_passed', summary: '同一扫描器二次复测通过。', details: { tool_name: 'demo.scanner.retest@1', duration_ms: 8, attempt: 2 }, created_at: '2026-09-07T09:07:00Z' },
      ],
    }
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/metrics')) return Promise.resolve(new Response(JSON.stringify({ total: 1, open: 0, critical_open: 0, awaiting_approval: 0, verification_pending: 0, closed: 1, accepted_risk: 0 })))
      return Promise.resolve(new Response(JSON.stringify({ items: [workflowFinding] })))
    })
    render(<VulnerabilitiesPage />)
    fireEvent.click(await screen.findByRole('button', { name: '展开详情' }))
    fireEvent.click(await screen.findByRole('button', { name: '查看智能体工作链' }))

    expect(screen.getByRole('dialog', { name: '动态漏洞处置工作链' })).toBeVisible()
    const chain = screen.getByRole('list', { name: '漏洞智能体工作链' })
    expect(chain).toBeVisible()
    expect(within(chain).getAllByRole('listitem')).toHaveLength(workflowFinding.events.length)
    expect(within(chain).queryByText('闭环反馈')).not.toBeInTheDocument()
    expect(within(chain).getByText('模拟扫描器复测失败')).toBeVisible()
    expect(within(chain).getByText('智能体根据反馈重新规划')).toBeVisible()
    expect(within(chain).getByText(/demo\.service\.restart@1/)).toBeVisible()
    expect(screen.getAllByText(/策略检查通过并自动授权组件升级/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/demo\.patch\.apply@1/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/同一扫描器二次复测通过/).length).toBeGreaterThan(0)
    expect(screen.getByText('完整工作回执')).toBeVisible()
    expect(screen.queryByText(/隐藏思维|思维链/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '关闭智能体工作链' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
