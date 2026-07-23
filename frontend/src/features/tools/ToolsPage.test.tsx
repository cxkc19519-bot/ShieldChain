import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ToolsPage } from './ToolsPage'

const api = vi.hoisted(() => ({ getToolTrace: vi.fn(), decideToolCall: vi.fn(), controlToolCall: vi.fn(), setEmergencyStop: vi.fn() }))
vi.mock('./api', () => api)
const ID = '11111111-1111-4111-8111-111111111111'

beforeEach(() => Object.values(api).forEach((mock) => mock.mockReset()))

describe('ToolsPage', () => {
  it('renders the public execution trace without private material', async () => {
    api.getToolTrace.mockResolvedValue({ run_id: ID, calls: [{ id: ID, tool_name: 'block_ip', tool_version: '1', status: 'awaiting_approval', reason: 'approval_required', target: '203.0.113.8', policy_outcome: 'approval_required', approval_outcome: null, attempt_outcomes: ['started'], verification_outcome: null, evidence_ids: [ID], created_at: '2026-07-23T00:00:00Z', updated_at: '2026-07-23T00:00:00Z' }] })
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))
    expect(await screen.findByText('block_ip')).toBeVisible()
    expect(screen.getByText('203.0.113.8')).toBeVisible()
    expect(screen.getByText(/不展示原始结果/)).toBeVisible()
    expect(screen.queryByText(/token_digest|chain_of_thought|raw_prompt/)).not.toBeInTheDocument()
  })
})
