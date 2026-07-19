import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { KnowledgePage } from './KnowledgePage'

const api = vi.hoisted(() => ({
  createKnowledgeBase: vi.fn(), deleteDocument: vi.fn(), listDocuments: vi.fn(),
  listKnowledgeBases: vi.fn(), publishVersion: vi.fn(), rebuildDocumentVersion: vi.fn(),
  retrieveKnowledge: vi.fn(), rollbackVersion: vi.fn(), runEvaluation: vi.fn(), uploadDocument: vi.fn(),
}))
vi.mock('./api', () => api)

const ID = '11111111-1111-4111-8111-111111111111'
const NOW = '2026-07-19T00:00:00Z'
const base = { id: ID, name: '安全规范', status: 'draft', default_sensitivity: 'internal', version_policy: 'immutable', created_at: NOW, updated_at: NOW }
const version = { id: ID, document_id: ID, version_number: 1, parsing_status: 'succeeded', chunking_status: 'succeeded', index_status: 'succeeded', chunking_strategy: 'semantic', chunking_failure_category: null, created_at: NOW, published_at: null }
const document = { id: ID, knowledge_base_id: ID, original_filename: 'guide.pdf', media_type: 'application/pdf', status: 'draft', current_version_id: null, created_at: NOW, updated_at: NOW, versions: [version] }

beforeEach(() => {
  Object.values(api).forEach((mock) => mock.mockReset())
  api.listKnowledgeBases.mockResolvedValue([base])
  api.listDocuments.mockResolvedValue([document])
})

describe('KnowledgePage', () => {
  it('shows document lifecycle and truthful structured refusal/degradation', async () => {
    const user = userEvent.setup()
    api.retrieveKnowledge.mockResolvedValue({
      query: '恶意宏', answer: null, refusal_reason: 'insufficient_evidence', hits: [], citations: [],
      degradations: [{ kind: 'vector_degraded', error_category: 'timeout', message: '向量服务超时，已保留 BM25' }],
    })
    render(<KnowledgePage />)

    expect(await screen.findByText('guide.pdf')).toBeVisible()
    expect(screen.getByRole('button', { name: '发布' })).toBeVisible()
    await user.type(screen.getByLabelText('检索知识库'), '恶意宏')
    await user.click(screen.getByRole('button', { name: '混合检索' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('insufficient_evidence')
    expect(screen.getByText(/vector_degraded\/timeout/)).toBeVisible()
    expect(screen.queryByText('已生成可信答案')).not.toBeInTheDocument()
  })

  it('accepts only supported local formats and rejects an empty upload', async () => {
    render(<KnowledgePage />)
    await screen.findByText('guide.pdf')
    const input = screen.getByLabelText('上传本地文档')
    fireEvent.submit(input.closest('form') as HTMLFormElement)

    expect(input).toHaveAttribute('accept', '.pdf,.docx,.xlsx,.csv,.txt,.md,.html')
    expect(screen.getByRole('alert')).toHaveTextContent('请选择一个非空文档')
    expect(api.uploadDocument).not.toHaveBeenCalled()
  })

  it('aborts page-owned loading on unmount', async () => {
    let observed: AbortSignal | undefined
    api.listKnowledgeBases.mockImplementation((signal: AbortSignal) => {
      observed = signal
      return new Promise(() => undefined)
    })
    const view = render(<KnowledgePage />)
    await waitFor(() => expect(observed).toBeDefined())
    view.unmount()
    expect(observed?.aborted).toBe(true)
  })
})
