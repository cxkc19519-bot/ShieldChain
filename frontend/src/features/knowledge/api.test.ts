import { afterEach, describe, expect, it, vi } from 'vitest'

import { createKnowledgeBase, deleteDocument, retrieveKnowledge, uploadDocument } from './api'

const ID = '11111111-1111-4111-8111-111111111111'
const NOW = '2026-07-19T00:00:00Z'
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
})
const base = {
  id: ID, name: '安全规范', status: 'draft', default_sensitivity: 'internal',
  version_policy: 'immutable', created_at: NOW, updated_at: NOW,
}
const version = {
  id: ID, document_id: ID, version_number: 1, parsing_status: 'succeeded',
  chunking_status: 'succeeded', index_status: 'succeeded', chunking_strategy: 'semantic',
  chunking_failure_category: null, created_at: NOW, published_at: null,
}
const document = {
  id: ID, knowledge_base_id: ID, original_filename: 'guide.pdf', media_type: 'application/pdf',
  status: 'draft', current_version_id: null, created_at: NOW, updated_at: NOW, versions: [version],
}

afterEach(() => vi.restoreAllMocks())

describe('knowledge API client', () => {
  it('creates and retrieves with strict snake_case payloads and never sends tenant_id', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(base, 201))
      .mockResolvedValueOnce(response({ query: '钓鱼', answer: null, refusal_reason: 'insufficient_evidence', hits: [], citations: [], degradations: [] }))
    vi.stubGlobal('fetch', fetchMock)

    await createKnowledgeBase('安全规范')
    await retrieveKnowledge(ID, '钓鱼')

    const createBody = String((fetchMock.mock.calls[0]?.[1] as RequestInit).body)
    const retrievalBody = String((fetchMock.mock.calls[1]?.[1] as RequestInit).body)
    expect(JSON.parse(createBody)).toEqual({ name: '安全规范', default_sensitivity: 'internal', version_policy: 'immutable' })
    expect(JSON.parse(retrievalBody)).toEqual({ knowledge_base_ids: [ID], query: '钓鱼', limit: 8 })
    expect(`${createBody}${retrievalBody}`).not.toContain('tenant_id')
  })

  it('uploads only a File plus controlled metadata and deletes with DELETE', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(document, 202))
      .mockResolvedValueOnce(response({ operation: 'delete', status: 'accepted', document_id: ID, version_id: null }, 202))
    vi.stubGlobal('fetch', fetchMock)
    const file = new File(['safe'], 'guide.pdf', { type: 'application/pdf' })

    await expect(uploadDocument(ID, file)).resolves.toEqual(document)
    await deleteDocument(ID)

    const upload = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(upload.body).toBeInstanceOf(FormData)
    expect([...(upload.body as FormData).keys()]).toEqual(['file', 'sensitivity', 'permission_tags'])
    expect([...(upload.body as FormData).keys()]).not.toContain('tenant_id')
    expect(fetchMock).toHaveBeenLastCalledWith(`/api/v1/documents/${ID}`, expect.objectContaining({ method: 'DELETE' }))
  })
})
