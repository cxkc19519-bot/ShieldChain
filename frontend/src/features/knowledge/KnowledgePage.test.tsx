import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { KnowledgePage } from './KnowledgePage'

const api = vi.hoisted(() => ({
  createKnowledgeBase: vi.fn(), deleteDocument: vi.fn(), deleteKnowledgeBase: vi.fn(), listDocumentChunks: vi.fn(), listDocuments: vi.fn(),
  importSecurityVerticalPack: vi.fn(), listKnowledgeBases: vi.fn(), publishVersion: vi.fn(), rebuildDocumentVersion: vi.fn(),
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

  it('imports the reviewed security vertical pack and shows its review window', async () => {
    const user = userEvent.setup()
    api.importSecurityVerticalPack.mockResolvedValue({
      pack_id: 'shieldchain-security-vertical',
      pack_version: '2026.09.3',
      usage_policy: '归档清单明确列出的官方公开 PDF 与 HTML 快照。',
      knowledge_base_id: ID,
      verified_at: '2026-09-02',
      review_due_at: '2026-10-02',
      imported: ['policy.md', 'kev.md', 'attack.md'],
      skipped: ['maintenance.md'],
    })
    render(<KnowledgePage />)
    await screen.findByText('guide.pdf')

    await user.click(screen.getByRole('button', { name: '导入安全垂直知识包' }))

    expect(api.importSecurityVerticalPack).toHaveBeenCalledOnce()
    expect(await screen.findByTestId('curated-pack-summary')).toHaveTextContent(
      '权威知识包 2026.09.3 · 核验 2026-09-02 · 下次复核 2026-10-02 · 新增 3 · 已存在 1。归档清单明确列出的官方公开 PDF 与 HTML 快照。',
    )
  })

  it('shows per-case RAG evaluation evidence and failure reasons', async () => {
    const user = userEvent.setup()
    api.runEvaluation.mockResolvedValue({
      dataset_id: 'shieldchain-security-vertical-v1', dataset_version: '1.0.0',
      dataset_sha256: 'a'.repeat(64), case_count: 1,
      metrics: { recall_at_k: 0 }, thresholds: { recall_at_k: 0.75 },
      quality_gate_passed: false,
      case_results: [{
        case_id: 'zh-policy', language: 'zh', query: '法规要求是什么？',
        expected_document_ids: ['policy.md'], baseline_document_ids: ['noise.md'],
        retrieved_document_ids: ['noise.md'], cited_document_ids: ['noise.md'],
        expected_refusal: false, actual_refusal: false, recall_at_k: 0,
        reciprocal_rank: 0, citation_precision: 0, expected_citation_recall: 0,
        extractive_faithfulness: 0,
        latency_ms: 4, failed_call_count: 1, passed: false,
        failure_reasons: ['missing_relevant_document', 'unsupported_citation'],
      }],
    })
    render(<KnowledgePage />)
    await screen.findByText('guide.pdf')

    await user.click(screen.getByRole('button', { name: '运行评测' }))
    expect(await screen.findByText(/zh-policy/)).toBeVisible()
    await user.click(screen.getByText(/zh-policy/))

    expect(screen.getByText('法规要求是什么？')).toBeVisible()
    expect(screen.getByText('missing_relevant_document；unsupported_citation')).toBeVisible()
    expect(screen.getByText('policy.md')).toBeVisible()
    expect(screen.getByText('抽取忠实度')).toBeVisible()
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

  it('shows an explicit loading state before a truthful empty state', async () => {
    let resolveBases: ((value: typeof base[]) => void) | undefined
    api.listKnowledgeBases.mockReturnValue(new Promise((resolve) => { resolveBases = resolve }))

    render(<KnowledgePage />)
    expect(screen.getByText('正在加载知识库')).toBeVisible()

    resolveBases?.([])
    expect(await screen.findAllByText('暂无可用知识库')).toHaveLength(2)
    expect(api.listDocuments).not.toHaveBeenCalled()
  })

  it('keeps the primary workflow keyboard reachable', async () => {
    const user = userEvent.setup()
    render(<KnowledgePage />)
    await screen.findByText('guide.pdf')

    await user.tab()
    expect(screen.getByRole('button', { name: '导入安全垂直知识包' })).toHaveFocus()
    await user.tab()
    expect(screen.getByLabelText('新知识库名称')).toHaveFocus()
    await user.type(screen.getByLabelText('新知识库名称'), '应急手册')
    await user.tab()
    expect(screen.getByRole('button', { name: '创建' })).toHaveFocus()
  })

  it('does not render server-only sensitive fields', async () => {
    api.listKnowledgeBases.mockResolvedValue([{ ...base, tenant_id: 'tenant-secret', raw_prompt: 'hidden prompt' }])
    api.listDocuments.mockResolvedValue([{ ...document, storage_path: 'C:\\private\\guide.pdf', access_token: 'token-secret' }])

    render(<KnowledgePage />)
    await screen.findByText('guide.pdf')

    expect(screen.queryByText('tenant-secret')).not.toBeInTheDocument()
    expect(screen.queryByText('hidden prompt')).not.toBeInTheDocument()
    expect(screen.queryByText('C:\\private\\guide.pdf')).not.toBeInTheDocument()
    expect(screen.queryByText('token-secret')).not.toBeInTheDocument()
  })
})
