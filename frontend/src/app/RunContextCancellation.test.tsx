import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterAll, beforeAll, expect, it, vi } from 'vitest'

import { AgentsPage } from '../features/agents/AgentsPage'
import { RunContextProvider } from './RunContext'
import { RunContextSwitcher } from './RunContextSwitcher'

const FIRST_RUN = '11111111-1111-4111-8111-111111111111'
const NEXT_RUN = '22222222-2222-4222-8222-222222222222'
const api = vi.hoisted(() => ({ getCollaborationTrajectory: vi.fn() }))
vi.mock('../features/agents/api', () => api)

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
  let requestSignal: AbortSignal | undefined
  api.getCollaborationTrajectory.mockImplementation((_runId: string, signal: AbortSignal) => {
    requestSignal = signal
    return new Promise(() => undefined)
  })
  const router = createMemoryRouter([{
    path: '*',
    element: <RunContextProvider><RunContextSwitcher /><AgentsPage /></RunContextProvider>,
  }], { initialEntries: [`/agents?run_id=${FIRST_RUN}`] })
  const user = userEvent.setup()
  render(<RouterProvider router={router} />)

  await user.click(screen.getByRole('button', { name: '查看协作轨迹' }))
  expect(requestSignal?.aborted).toBe(false)

  const switcher = screen.getByRole('form', { name: '当前案件与运行' })
  const input = within(switcher).getByLabelText('运行 ID')
  await user.clear(input)
  await user.type(input, NEXT_RUN)
  await user.click(within(switcher).getByRole('button', { name: '应用上下文' }))

  expect(requestSignal?.aborted).toBe(true)
  expect(screen.getByLabelText('调查运行 ID')).toHaveValue(NEXT_RUN)
})
