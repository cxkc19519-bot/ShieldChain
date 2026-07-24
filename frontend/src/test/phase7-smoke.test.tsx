import { cleanup, render, screen } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { appRoutes } from '../app/router'

const offline = vi.hoisted(() => ({
  getLiveness: vi.fn(),
  listKnowledgeBases: vi.fn(),
}))

vi.mock('../api/client', () => ({ getLiveness: offline.getLiveness }))
vi.mock('../features/knowledge/api', () => ({
  createKnowledgeBase: vi.fn(), deleteDocument: vi.fn(), listDocuments: vi.fn(),
  listKnowledgeBases: offline.listKnowledgeBases, publishVersion: vi.fn(), rebuildDocumentVersion: vi.fn(),
  retrieveKnowledge: vi.fn(), rollbackVersion: vi.fn(), runEvaluation: vi.fn(), uploadDocument: vi.fn(),
}))

const pages = [
  ['/', '运营总览'],
  ['/events', '事件调查'],
  ['/agents', '智能体与 ReAct 工作台'],
  ['/knowledge', '知识库工作台'],
  ['/response', '处置中心'],
  ['/reports', '报告与审计'],
] as const

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  offline.getLiveness.mockReset().mockResolvedValue({ status: 'ok' })
  offline.listKnowledgeBases.mockReset().mockResolvedValue([])
  fetchMock = vi.fn(() => Promise.reject(new Error('Phase 7 smoke forbids network access')))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('Phase 7 offline cross-page smoke', () => {
  it('renders every product workspace with truthful empty simulation boundaries', async () => {
    for (const [path, heading] of pages) {
      const router = createMemoryRouter(appRoutes, { initialEntries: [path] })
      const view = render(<RouterProvider router={router} />)
      expect(await screen.findByRole('heading', { name: heading, level: 2 })).toBeVisible()
      expect(screen.getByText('离线仿真环境')).toBeVisible()
      expect(screen.queryByText(/raw_prompt|chain_of_thought|token_digest|tenant_id|principal_id/)).not.toBeInTheDocument()
      view.unmount()
    }
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
