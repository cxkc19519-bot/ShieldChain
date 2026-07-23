import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AgentsPage } from './AgentsPage'

const api = vi.hoisted(() => ({ getCollaborationTrajectory: vi.fn() }))
vi.mock('./api', () => api)
const ID = '11111111-1111-4111-8111-111111111111'

beforeEach(() => api.getCollaborationTrajectory.mockReset())

describe('AgentsPage', () => {
  it('renders only the public collaboration trajectory fields', async () => {
    api.getCollaborationTrajectory.mockResolvedValue({
      run_id: ID, case_id: ID, phase: 'investigation', revision: 2,
      shared_summary: '钓鱼调查进行中', confirmed_facts: ['已确认外连'],
      budget: { steps_used: 2, step_limit: 10, tokens_used: 200, token_limit: 1000, tool_calls_used: 0, tool_call_limit: 5 },
      reason_codes: ['evidence_insufficient'],
      role_statuses: [{ role: 'alert_triage', status: 'completed', summary: '需要调查', reason_code: null, citations: [], updated_at: null }],
      handoffs: [{ id: ID, sender: 'alert_triage', receiver: 'threat_investigation', conclusion: '检查终端', confidence: .8, open_questions: [], recommended_actions: [], citations: [], created_at: '2026-07-23T00:00:00Z' }],
      citations: [{ id: ID, kind: 'evidence', source_id: 'siem:1', observed_at: '2026-07-23T00:00:00Z', integrity_sha256: 'a'.repeat(64) }], updated_at: '2026-07-23T00:00:00Z',
    })
    render(<AgentsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看协作轨迹' }))
    expect(await screen.findByText('钓鱼调查进行中')).toBeVisible()
    expect(screen.getByText('alert_triage → threat_investigation')).toBeVisible()
    expect(screen.getByText('siem:1')).toBeVisible()
    expect(screen.getByText('evidence_insufficient')).toBeVisible()
    expect(screen.getByText(/不展示私有上下文/)).toBeVisible()
    expect(screen.queryByText(/思维过程内容/)).not.toBeInTheDocument()
  })
})
