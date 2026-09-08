import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ToolsPage } from './ToolsPage'

const api = vi.hoisted(() => ({ getToolTrace: vi.fn(), getResponsePlan: vi.fn(), decideResponsePlan: vi.fn(), decideToolCall: vi.fn(), controlToolCall: vi.fn(), setEmergencyStop: vi.fn() }))
const mcpApi = vi.hoisted(() => ({ getMcpRunCalls: vi.fn() }))
const agentApi = vi.hoisted(() => ({ getCollaborationTrajectory: vi.fn() }))
const operationsApi = vi.hoisted(() => ({ listOperationsReports: vi.fn() }))
vi.mock('./api', () => api)
vi.mock('../mcp/api', () => mcpApi)
vi.mock('../agents/api', () => agentApi)
vi.mock('../operations/api', () => operationsApi)
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
  Object.values(agentApi).forEach((mock) => mock.mockReset())
  Object.values(operationsApi).forEach((mock) => mock.mockReset())
  api.getResponsePlan.mockRejectedValue(new Error('Response plan not found'))
  mcpApi.getMcpRunCalls.mockResolvedValue([])
  agentApi.getCollaborationTrajectory.mockRejectedValue(new Error('Agent trajectory not found'))
  operationsApi.listOperationsReports.mockResolvedValue([])
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

  it('shows an evidence-backed attack investigation timeline before response actions', async () => {
    agentApi.getCollaborationTrajectory.mockResolvedValue({
      run_id: ID, case_id: ID_2, phase: 'action_planned', revision: 3,
      shared_summary: '已关联异常流量、终端进程与身份账号。',
      confirmed_facts: ['终端存在异常外联', '账号与进程时间一致'], reason_codes: [],
      role_statuses: [], budget: { step_limit: 10, steps_used: 4, loop_limit: 3, loops_used: 1, time_limit_seconds: 300, time_used_seconds: 12, token_limit: 1000, tokens_used: 300, cost_limit_usd: 1, cost_used_usd: 0, tool_call_limit: 10, tool_calls_used: 2 },
      handoffs: [{ id: ID_3, sender: 'alert_triage', receiver: 'threat_investigation', conclusion: '异常流量由 powershell.exe 发起，并关联到账号 user01。', confidence: .92, open_questions: ['确认账号业务用途'], recommended_actions: [], citations: [{ id: ID, kind: 'evidence', source_id: 'wazuh:event-7', observed_at: '2026-07-23T00:00:00Z', integrity_sha256: 'a'.repeat(64) }], created_at: '2026-07-23T00:00:00Z' }],
      citations: [], updated_at: '2026-07-23T00:00:00Z',
    })
    api.getToolTrace.mockResolvedValue({ run_id: ID, calls: [] })
    mcpApi.getMcpRunCalls.mockResolvedValue([{ id: ID, role: 'threat_investigation', direction: 'internal', provider_kind: 'builtin', provider_id: 'local', tool_alias: 'query_process_tree', catalog_revision: '1', schema_revision: '1', status: 'succeeded', reason_code: null, result_count: 1, summary: '定位到终端进程树。', duration_ms: 12, attempt: 1, truncated: false, created_at: '2026-07-23T00:00:01Z', finished_at: '2026-07-23T00:00:02Z' }])
    render(<ToolsPage />)
    fireEvent.change(screen.getByLabelText('调查运行 ID'), { target: { value: ID } })
    fireEvent.click(screen.getByRole('button', { name: '查看处置轨迹' }))

    expect(await screen.findByRole('heading', { name: '智能体攻击调查时间线' })).toBeVisible()
    expect(screen.getByText('异常流量由 powershell.exe 发起，并关联到账号 user01。')).toBeVisible()
    expect(screen.getByText('wazuh:event-7')).toBeVisible()
    expect(screen.getAllByText('定位到终端进程树。')).toHaveLength(2)
    expect(screen.getByText(/不展示隐藏思维链/)).toBeVisible()
  })

  it('uses the public operations report timeline for an automatic Wazuh investigation', async () => {
    api.getToolTrace.mockRejectedValue(new Error('Trusted tool trace not found'))
    operationsApi.listOperationsReports.mockResolvedValue([{
      id: 'report-1', run_id: ID, run_status: 'completed', generated_at: '2026-09-07T15:56:47Z',
      start_at: '2026-09-07T15:50:00Z', end_at: '2026-09-07T16:00:00Z', agent_name: '安全运营报告智能体', model: 'shieldchain-qwen3-30b',
      stages: [], collaboration: [], tool_calls: [], response_plan: null, cross_domain: [], markdown: '', html: '',
      reasoning_trace: [{ sequence: 1, phase: 'observe', title: '观测：发现异常网络流量', detail: 'NTA 告警达到调查阈值。', evidence: ['wazuh:alert-1'], domains: ['网络流量'], status: 'completed', confidence: .9 }],
      closure: { status: 'analysis_complete', observed: '已完成隔离回放告警调查。', decision: '建议人工复核。', action: '未执行动作。', verification: '等待验证。', feedback: '补充证据后重规划。', human_approval_required: true },
    }])
    render(<ToolsPage initialRunId={ID} embedded />)

    expect(await screen.findByRole('heading', { name: '智能体攻击调查时间线' })).toBeVisible()
    expect(screen.getByText('观测：发现异常网络流量')).toBeVisible()
    expect(screen.getByText('NTA 告警达到调查阈值。')).toBeVisible()
    expect(screen.getByText('wazuh:alert-1')).toBeVisible()
    expect(screen.queryByText('该运行尚未生成多智能体协作轨迹。')).not.toBeInTheDocument()
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
