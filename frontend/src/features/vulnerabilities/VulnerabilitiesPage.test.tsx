import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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
    details: { agent_status: 'completed', model: 'shieldchain-qwen3-30b', priority: 'P0',
      affected_assessment: '当前资产版本可能位于受影响范围，仍需核对厂商公告。',
      remediation: '建议在批准的维护窗口升级到修复版本。', verification: '使用同一扫描器复测并保留扫描任务证据。' },
    created_at: '2026-09-07T09:01:00Z',
  },
  events: [],
}

describe('VulnerabilitiesPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/metrics')) return Promise.resolve(new Response(JSON.stringify({ total: 1, open: 1, critical_open: 1, awaiting_approval: 1, verification_pending: 0, closed: 0, accepted_risk: 0 })))
      if (init?.method === 'POST') return Promise.resolve(new Response(JSON.stringify({ finding: { ...finding, status: 'remediation_approved' }, event: {} }), { status: 201 }))
      return Promise.resolve(new Response(JSON.stringify({ items: [finding] })))
    }))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows model evidence and requires human rationale before approval', async () => {
    render(<VulnerabilitiesPage />)
    expect(await screen.findByText('CVE-2026-12345')).toBeVisible()
    expect(screen.getByText(/shieldchain-qwen3-30b/)).toBeVisible()
    const approve = screen.getByRole('button', { name: /批准修复/ })
    expect(approve).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/至少 10 个字符/), { target: { value: '已核对厂商公告和资产版本，确认需要修复。' } })
    expect(approve).toBeEnabled()
    fireEvent.click(approve)
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/decision'), expect.objectContaining({ method: 'POST' })))
  })
})
