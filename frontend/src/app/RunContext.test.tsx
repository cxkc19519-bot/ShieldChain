import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider, useLocation } from 'react-router-dom'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { RunContextProvider, useRunContext } from './RunContext'
import { RunContextSwitcher } from './RunContextSwitcher'

const INCIDENT_ID = '11111111-1111-4111-8111-111111111111'
const RUN_ID = '22222222-2222-4222-8222-222222222222'
const NativeRequest = globalThis.Request

beforeAll(() => {
  vi.stubGlobal('Request', class CompatibleRequest extends NativeRequest {
    constructor(input: RequestInfo | URL, init?: RequestInit) {
      super(input, init ? { ...init, signal: undefined } : init)
    }
  })
})

afterAll(() => vi.stubGlobal('Request', NativeRequest))

function Probe() {
  const context = useRunContext()
  const location = useLocation()
  return <><span data-testid="incident">{context.incidentId ?? 'none'}</span><span data-testid="run">{context.runId ?? 'none'}</span><span data-testid="search">{location.search}</span><RunContextSwitcher /></>
}

function renderContext(path = '/') {
  const router = createMemoryRouter([{ path: '*', element: <RunContextProvider><Probe /></RunContextProvider> }], { initialEntries: [path] })
  return render(<RouterProvider router={router} />)
}

beforeEach(() => window.sessionStorage.clear())

describe('RunContextProvider', () => {
  it('prefers URL context and persists only incident and run identifiers', async () => {
    window.sessionStorage.setItem('shieldchain.run_id', INCIDENT_ID)
    window.sessionStorage.setItem('tenant_id', 'must-not-read')
    renderContext(`/?incident_id=${INCIDENT_ID}&run_id=${RUN_ID}`)

    expect(screen.getByTestId('incident')).toHaveTextContent(INCIDENT_ID)
    expect(screen.getByTestId('run')).toHaveTextContent(RUN_ID)
    await waitFor(() => {
      expect(window.sessionStorage.getItem('shieldchain.incident_id')).toBe(INCIDENT_ID)
      expect(window.sessionStorage.getItem('shieldchain.run_id')).toBe(RUN_ID)
    })
    expect([...Array(window.sessionStorage.length)].map((_, index) => window.sessionStorage.key(index))).not.toContain('principal_id')
  })

  it('falls back to session storage and supports manual replacement and clearing', async () => {
    window.sessionStorage.setItem('shieldchain.incident_id', INCIDENT_ID)
    const user = userEvent.setup()
    renderContext('/agents')

    expect(screen.getByLabelText('事件 ID')).toHaveValue(INCIDENT_ID)
    await user.type(screen.getByLabelText('运行 ID'), RUN_ID)
    await user.click(screen.getByRole('button', { name: '应用上下文' }))
    expect(screen.getByTestId('search')).toHaveTextContent(`incident_id=${INCIDENT_ID}`)
    expect(screen.getByTestId('search')).toHaveTextContent(`run_id=${RUN_ID}`)

    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(screen.getByTestId('run')).toHaveTextContent('none')
    expect(window.sessionStorage.getItem('shieldchain.run_id')).toBeNull()
  })

  it('rejects malformed identifiers instead of persisting them', async () => {
    const user = userEvent.setup()
    renderContext()
    await user.type(screen.getByLabelText('运行 ID'), 'not-a-uuid')
    await user.click(screen.getByRole('button', { name: '应用上下文' }))

    expect(screen.getByTestId('run')).toHaveTextContent('none')
    expect(window.sessionStorage.getItem('shieldchain.run_id')).toBeNull()
    expect(screen.getByTestId('search')).not.toHaveTextContent('not-a-uuid')
  })
})
