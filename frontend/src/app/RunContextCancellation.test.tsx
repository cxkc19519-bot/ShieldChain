import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterAll, beforeAll, expect, it, vi } from 'vitest'

import { AgentsPage } from '../features/agents/AgentsPage'
import { RunContextProvider } from './RunContext'
import { RunContextSwitcher } from './RunContextSwitcher'

const FIRST_RUN = '11111111-1111-4111-8111-111111111111'
const NEXT_RUN = '22222222-2222-4222-8222-222222222222'
const api = vi.hoisted(() => ({ getCollaborationTrajectory: vi.fn(), listAgentRuns: vi.fn() }))
vi.mock('../features/agents/api', () => api)
vi.mock('../features/agents/reactApi', () => ({ getReactTrajectory: vi.fn().mockRejectedValue(new Error('ReAct trajectory not found')), controlReactLoop: vi.fn() }))
vi.mock('../features/mcp/api', () => ({ getMcpRunCalls: vi.fn().mockResolvedValue([]) }))

const NativeRequest = globalThis.Request
beforeAll(() => {
  vi.stubGlobal('Request', class CompatibleRequest extends NativeRequest {
    constructor(input: RequestInfo | URL, init?: RequestInit) {
      super(input, init ? { ...init, signal: undefined } : init)
    }
  })
})
afterAll(() => vi.stubGlobal('Request', NativeRequest))

it('aborts the previous page request when the shared run changes', async () => {
  const requestSignals: AbortSignal[] = []
  api.listAgentRuns.mockResolvedValue([{
    run_id: FIRST_RUN, incident_id: null, incident_tracking_id: 'WAZ-2026-0001',
    threat_label: '测试告警', endpoint: 'nta-replay', status: 'analyzing',
    created_at: '2026-09-07T00:00:00Z', updated_at: '2026-09-07T00:00:00Z',
  }])
  api.getCollaborationTrajectory.mockImplementation((_runId: string, signal: AbortSignal) => {
    requestSignals.push(signal)
    return new Promise(() => undefined)
  })
  const router = createMemoryRouter([{
    path: '*',
    element: <RunContextProvider><RunContextSwitcher /><AgentsPage /></RunContextProvider>,
  }], { initialEntries: [`/agents?run_id=${FIRST_RUN}`] })
  const user = userEvent.setup()
  render(<RouterProvider router={router} />)

  await waitFor(() => expect(requestSignals).toHaveLength(1))
  expect(requestSignals[0]?.aborted).toBe(false)

  const switcher = screen.getByRole('form', { name: '当前案件与运行' })
  const input = within(switcher).getByLabelText('运行 ID')
  await user.clear(input)
  await user.type(input, NEXT_RUN)
  await user.click(within(switcher).getByRole('button', { name: '应用上下文' }))

  await waitFor(() => expect(requestSignals).toHaveLength(2))
  expect(requestSignals[0]?.aborted).toBe(true)
  expect(requestSignals[1]?.aborted).toBe(false)
  expect(within(switcher).getByLabelText('运行 ID')).toHaveValue(NEXT_RUN)
})
