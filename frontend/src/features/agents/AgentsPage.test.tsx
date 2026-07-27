import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AgentsPage } from './AgentsPage'

const api = vi.hoisted(() => ({ getCollaborationTrajectory: vi.fn() }))
const reactApi = vi.hoisted(() => ({ getReactTrajectory: vi.fn(), controlReactLoop: vi.fn() }))
vi.mock('./api', () => api)
vi.mock('./reactApi', () => reactApi)
const ID = '11111111-1111-4111-8111-111111111111'
const budget = { steps_used: 2, step_limit: 10, loops_used: 1, loop_limit: 3, time_used_seconds: 5, time_limit_seconds: 60, tokens_used: 200, token_limit: 1000, cost_used_usd: 0, cost_limit_usd: 1, tool_calls_used: 0, tool_call_limit: 5 }

beforeEach(() => { api.getCollaborationTrajectory.mockReset(); reactApi.getReactTrajectory.mockReset().mockRejectedValue(new Error('ReAct trajectory not found')); reactApi.controlReactLoop.mockReset() })

describe('AgentsPage', () => {
  it('renders only the public collaboration trajectory fields', async () => {
    api.getCollaborationTrajectory.mockResolvedValue({ run_id: ID, case_id: ID, phase: 'investigation', revision: 2, shared_summary: '钓鱼调查进行中', confirmed_facts: ['已确认外连'], budget, reason_codes: ['evidence_insufficient'], role_statuses: [{ role: 'alert_triage', status: 'completed', summary: '需要调查', reason_code: null, citations: [], updated_at: null }], handoffs: [{ id: ID, sender: 'alert_triage', receiver: 'threat_investigation', conclusion: '检查终端', confidence: .8, open_questions: [], recommended_actions: [], citations: [], created_at: '2026-07-23T00:00:00Z' }], citations: [{ id: ID, kind: 'evidence', source_id: 'siem:1', observed_at: '2026-07-23T00:00:00Z', integrity_sha256: 'a'.repeat(64) }], updated_at: '2026-07-23T00:00:00Z' })
    render(<AgentsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看联合轨迹' }))
    expect(await screen.findByText('钓鱼调查进行中')).toBeVisible()
    expect(screen.getByText('alert_triage → threat_investigation')).toBeVisible()
    expect(screen.getByText('siem:1')).toBeVisible()
    expect(screen.getByText('evidence_insufficient')).toBeVisible()
    expect(screen.getByText(/不展示私有上下文/)).toBeVisible()
    expect(screen.getByRole('alert')).toHaveTextContent('未找到 ReAct 轨迹')
    expect(screen.queryByText(/思维过程内容/)).not.toBeInTheDocument()
  })

  it('combines controlled ReAct trajectory and uses the server control boundary', async () => {
    api.getCollaborationTrajectory.mockRejectedValue(new Error('Agent trajectory not found'))
    reactApi.getReactTrajectory.mockResolvedValue({ loop_id: ID, run_id: ID, case_id: ID, status: 'running', revision: 2, budget,
      observations: [{ id: ID, iteration: 1, source: 'tool_verification', status: 'failed', reason_code: 'verification_failed', citations: [], tool_call_id: null, verification_id: null, observed_at: '2026-07-24T00:00:00Z' }],
      assessments: [{ id: ID, observation_id: ID, category: 'transient', recoverable: true, confidence: .9, reason_code: 'retry_allowed', assessed_at: '2026-07-24T00:00:00Z' }],
      plan_revisions: [{ id: ID, revision: 2, parent_revision: 1, retained_action_ids: [], removed_action_ids: [ID], added_actions: [{ id: ID, action: 'verify', target: '203.0.113.8', expected_state: { blocked: true }, citations: [] }], reason: '切换验证路径', created_at: '2026-07-24T00:00:00Z' }],
      decisions: [{ id: ID, observation_id: ID, assessment_id: ID, decision: 'replan', reason_code: 'safe_retry', budget, plan_revision_id: ID, decided_at: '2026-07-24T00:00:00Z' }], controls: [], updated_at: '2026-07-24T00:00:00Z' })
    reactApi.controlReactLoop.mockResolvedValue({ loop_id: ID, status: 'human_takeover', revision: 3 })
    render(<AgentsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看联合轨迹' }))
    expect(await screen.findByText('tool_verification')).toBeVisible()
    expect(screen.getByRole('alert')).toHaveTextContent('未找到协作轨迹')
    expect(screen.getByText(/transient · 可恢复/)).toBeVisible()
    expect(screen.getByText('切换验证路径')).toBeVisible()
    expect(screen.getByText('replan')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '人工接管' }))
    expect(await screen.findByText(/人工接管成功/)).toBeVisible()
    expect(reactApi.controlReactLoop).toHaveBeenCalledWith(ID, 'takeover', '人工复核运行轨迹', expect.any(AbortSignal))
    expect(screen.queryByText(/chain_of_thought|raw_prompt|private_context/)).not.toBeInTheDocument()
  })
})
