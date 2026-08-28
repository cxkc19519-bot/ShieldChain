import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ToolsPage } from './ToolsPage'

const api = vi.hoisted(() => ({ getToolTrace: vi.fn(), getResponsePlan: vi.fn(), decideResponsePlan: vi.fn(), decideToolCall: vi.fn(), controlToolCall: vi.fn(), setEmergencyStop: vi.fn() }))
const mcpApi = vi.hoisted(() => ({ getMcpRunCalls: vi.fn() }))
vi.mock('./api', () => api)
vi.mock('../mcp/api', () => mcpApi)
const ID = '11111111-1111-4111-8111-111111111111'
const ID_2 = '22222222-2222-4222-8222-222222222222'
const ID_3 = '33333333-3333-4333-8333-333333333333'
const call = (status: string, id = ID) => ({
  id, plan_id: ID_2, plan_revision_id: ID_2, plan_action_id: ID_3,
  tool_name: 'block_ip', tool_version: '1', status, reason: 'approval_required',
  target: '203.0.113.8', policy_outcome: 'approval_required', risk: 'high', approval_outcome: null,
  attempt_outcomes: ['started'], verification_outcome: null, evidence_ids: [ID],
  created_at: '2026-07-23T00:00:00Z', updated_at: '2026-07-23T00:00:00Z',
})

beforeEach(() => {
  Object.values(api).forEach((mock) => mock.mockReset())
  Object.values(mcpApi).forEach((mock) => mock.mockReset())
  api.getResponsePlan.mockRejectedValue(new Error('Response plan not found'))
  mcpApi.getMcpRunCalls.mockResolvedValue([])
})

describe('ToolsPage', () => {
  it('renders the public execution trace without private material', async () => {
    api.getToolTrace.mockResolvedValue({ run_id: ID, calls: [{ ...call('awaiting_approval'), raw_prompt: 'private prompt', token_digest: 'secret digest' }] })
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))
    expect(await screen.findByText('block_ip')).toBeVisible()
    expect(screen.getByText('203.0.113.8')).toBeVisible()
    expect(screen.getByText('high')).toBeVisible()
    expect(screen.getByText(/不展示原始结果/)).toBeVisible()
    expect(screen.queryByText(/token_digest|chain_of_thought|raw_prompt/)).not.toBeInTheDocument()
    expect(screen.queryByText('private prompt')).not.toBeInTheDocument()
    expect(screen.queryByText('secret digest')).not.toBeInTheDocument()
  })

  it('exposes only controls allowed by each server status', async () => {
    api.getToolTrace.mockResolvedValue({
      run_id: ID,
      calls: [call('awaiting_approval'), call('paused', ID_2), call('executing', ID_3)],
    })
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))
    await screen.findAllByText('block_ip')

    expect(screen.getAllByRole('button', { name: '批准' })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '拒绝' })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '暂停' })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '恢复' })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '取消' })).toHaveLength(2)
  })

  it('shows loading and a truthful empty trace', async () => {
    let resolveTrace: ((value: { run_id: string; calls: never[] }) => void) | undefined
    api.getToolTrace.mockReturnValue(new Promise((resolve) => { resolveTrace = resolve }))
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))

    expect(screen.getByText('正在读取处置轨迹')).toBeVisible()
    resolveTrace?.({ run_id: ID, calls: [] })
    expect(await screen.findByText('没有公开处置调用')).toBeVisible()
  })

  it('aborts a page-owned trace request on unmount', async () => {
    let observed: AbortSignal | undefined
    api.getToolTrace.mockImplementation((_runId: string, signal: AbortSignal) => {
      observed = signal
      return new Promise(() => undefined)
    })
    const view = render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))

    await waitFor(() => expect(observed).toBeDefined())
    view.unmount()
    expect(observed?.aborted).toBe(true)
  })

  it('refreshes the trusted trace after a failed mutation', async () => {
    api.getToolTrace
      .mockResolvedValueOnce({ run_id: ID, calls: [call('awaiting_approval')] })
      .mockResolvedValueOnce({ run_id: ID, calls: [call('approved')] })
    api.decideToolCall.mockRejectedValue(new Error('审批状态已变化'))
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))
    await screen.findByText('awaiting_approval')

    fireEvent.click(screen.getByRole('button', { name: '批准' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('审批状态已变化')
    await waitFor(() => expect(api.getToolTrace).toHaveBeenCalledTimes(2))
    expect(screen.getByText('approved')).toBeVisible()
    expect(screen.queryByRole('button', { name: '批准' })).not.toBeInTheDocument()
  })

  it('separates plan acceptance, tool approval, execution, and verification', async () => {
    api.getResponsePlan.mockResolvedValue({
      plan_id: ID_2, run_id: ID, case_id: ID_3, status: 'proposed', current_revision: 0,
      revisions: [{ id: ID_2, revision: 0, parent_revision: null, public_summary: '建议封禁已确认来源。', reason_code: null, created_at: '2026-08-24T00:00:00Z', actions: [{
        id: ID_3, sequence: 1, tool_name: 'block_ip', tool_version: '1', target_type: 'ipv4', target: '203.0.113.8',
        depends_on: [], evidence_ids: [ID], public_reason: '证据已确认，等待操作员接受计划。', assessed_risk: 'high',
        approval_required: true, verification_tool: 'query_firewall_state', verification_version: '1', rollback_strategy: 'remove exact rule',
        call_id: null, call_status: null, verification_outcome: null, raw_prompt: 'private prompt',
      }] }], events: [], created_at: '2026-08-24T00:00:00Z', updated_at: '2026-08-24T00:00:00Z',
    })
    api.getToolTrace.mockResolvedValue({ run_id: ID, calls: [] })
    api.decideResponsePlan.mockResolvedValue({ plan_id: ID_2, status: 'awaiting_execution', revision: 0, calls: [] })
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))

    expect(await screen.findByText('建议封禁已确认来源。')).toBeVisible()
    expect(screen.getByText('尚未接受')).toBeVisible()
    expect(screen.getByText('必须审批')).toBeVisible()
    expect(screen.getByText('尚未创建调用')).toBeVisible()
    expect(screen.getByText('尚未验证')).toBeVisible()
    expect(screen.queryByText('private prompt')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '接受计划并进入逐动作策略' }))
    await waitFor(() => expect(api.decideResponsePlan).toHaveBeenCalledWith(ID_2, 'accept', 0, '人工复核后执行'))
  })

  it('keeps a successful automation restore when the current run has no trusted trace', async () => {
    api.getToolTrace.mockRejectedValue(new Error('Trusted tool trace not found'))
    api.setEmergencyStop.mockResolvedValue({ call_id: null, status: 'automation_enabled', revision: 2 })
    render(<ToolsPage initialRunId={ID} embedded />)
    await screen.findByText('部分公开数据暂不可用')

    const restore = screen.getByRole('button', { name: '恢复自动化' })
    await waitFor(() => expect(restore).not.toBeDisabled())
    fireEvent.click(restore)
    expect(await screen.findByText(/automation_enabled/)).toBeVisible()
    expect(api.getToolTrace).toHaveBeenCalledTimes(2)
  })})
