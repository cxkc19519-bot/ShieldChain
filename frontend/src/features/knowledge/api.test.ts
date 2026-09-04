import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  createKnowledgeBase,
  deleteDocument,
  importSecurityVerticalPack,
  retrieveKnowledge,
  runEvaluation,
  uploadDocument,
} from './api'

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

  it('strictly decodes the bundled security knowledge import result', async () => {
    const body = {
      pack_id: 'shieldchain-security-vertical', pack_version: '2026.09.3',
      usage_policy: '归档清单明确列出的官方公开 PDF 与 HTML 快照。',
      knowledge_base_id: ID, verified_at: '2026-09-02', review_due_at: '2026-10-02',
      imported: ['policy.md'], skipped: ['attack.md'],
    }
    const fetchMock = vi.fn().mockResolvedValue(response(body, 202))
    vi.stubGlobal('fetch', fetchMock)

    await expect(importSecurityVerticalPack()).resolves.toEqual(body)
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/knowledge-bases/imports/security-vertical',
      expect.objectContaining({ method: 'POST', body: '{}' }),
    )
  })

  it('runs the security vertical benchmark only against the selected base', async () => {
    const body = {
      dataset_id: 'shieldchain-security-vertical-v1', dataset_version: '1.0.0',
      dataset_sha256: 'a'.repeat(64), case_count: 12,
      metrics: { recall_at_k: 0.8 }, thresholds: { recall_at_k: 0.75 },
      case_results: [{
        case_id: 'zh-policy', language: 'zh', query: '法规要求是什么？',
        expected_document_ids: ['policy.md'], baseline_document_ids: ['noise.md'],
        retrieved_document_ids: ['policy.md'], cited_document_ids: ['policy.md'],
        expected_refusal: false, actual_refusal: false, recall_at_k: 1,
        reciprocal_rank: 1, citation_precision: 1, expected_citation_recall: 1,
        extractive_faithfulness: 1,
        latency_ms: 4, failed_call_count: 0, passed: true, failure_reasons: [],
      }], quality_gate_passed: false,
    }
    const fetchMock = vi.fn().mockResolvedValue(response(body))
    vi.stubGlobal('fetch', fetchMock)

    await expect(runEvaluation(ID)).resolves.toEqual(body)
    const requestBody = String((fetchMock.mock.calls[0]?.[1] as RequestInit).body)
    expect(JSON.parse(requestBody)).toEqual({
      dataset_id: 'shieldchain-security-vertical-v1',
      knowledge_base_ids: [ID],
      max_cases: 100,
    })
    expect(requestBody).not.toContain('tenant_id')
  })
})
