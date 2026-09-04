import type {
  CuratedPackImportSummary,
  EvaluationSummary,
  KnowledgeBase,
  KnowledgeChunk,
  KnowledgeDocument,
  RetrievalResult,
} from './types'

const API_ROOT = '/api/v1'
const REQUEST_TIMEOUT_MS = 90_000

export class KnowledgeApiError extends Error {
  readonly code: string | undefined
  readonly requestId: string | undefined
  readonly status: number | undefined

  constructor(message: string, options: { code?: string; requestId?: string; status?: number } = {}) {
    super(message)
    this.name = 'KnowledgeApiError'
    this.code = options.code
    this.requestId = options.requestId
    this.status = options.status
  }
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error()
  return value as Record<string, unknown>
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error()
  return value
}

function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error()
  return value
}

function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error()
  return value
}

function nullableText(value: unknown): string | null {
  return value === null ? null : text(value)
}

function nullableNumber(value: unknown): number | null {
  return value === null ? null : number(value)
}

function array<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Error()
  return value.map(parse)
}

function version(value: unknown) {
  const item = record(value)
  return {
    id: text(item.id), document_id: text(item.document_id), version_number: number(item.version_number),
    parsing_status: text(item.parsing_status) as KnowledgeDocument['versions'][number]['parsing_status'],
    chunking_status: text(item.chunking_status) as KnowledgeDocument['versions'][number]['chunking_status'],
    index_status: text(item.index_status) as KnowledgeDocument['versions'][number]['index_status'],
    chunking_strategy: text(item.chunking_strategy),
    chunking_failure_category: nullableText(item.chunking_failure_category),
    created_at: text(item.created_at), published_at: nullableText(item.published_at),
  }
}

function document(value: unknown): KnowledgeDocument {
  const item = record(value)
  return {
    id: text(item.id), knowledge_base_id: text(item.knowledge_base_id), original_filename: text(item.original_filename),
    media_type: text(item.media_type), status: text(item.status) as KnowledgeDocument['status'],
    current_version_id: nullableText(item.current_version_id), created_at: text(item.created_at),
    updated_at: text(item.updated_at),
    versions: array(item.versions, version),
  }
}

function knowledgeChunk(value: unknown): KnowledgeChunk {
  const item = record(value)
  return {
    id: text(item.id), ordinal: number(item.ordinal), offset: number(item.offset),
    length: number(item.length), text: text(item.text), integrity_sha256: text(item.integrity_sha256),
  }
}

function knowledgeBase(value: unknown): KnowledgeBase {
  const item = record(value)
  return {
    id: text(item.id), name: text(item.name), status: text(item.status) as KnowledgeBase['status'],
    default_sensitivity: text(item.default_sensitivity) as KnowledgeBase['default_sensitivity'],
    version_policy: text(item.version_policy), created_at: text(item.created_at), updated_at: text(item.updated_at),
  }
}

function retrieval(value: unknown): RetrievalResult {
  const item = record(value)
  return {
    query: text(item.query), answer: nullableText(item.answer),
    refusal_reason: nullableText(item.refusal_reason) as RetrievalResult['refusal_reason'],
    hits: array(item.hits, (entry) => {
      const hit = record(entry)
      return {
        chunk_id: text(hit.chunk_id), knowledge_base_id: text(hit.knowledge_base_id),
        document_id: text(hit.document_id), document_version_id: text(hit.document_version_id),
        document_title: text(hit.document_title), excerpt: text(hit.excerpt),
        heading_path: array(hit.heading_path, text), page_number: nullableNumber(hit.page_number),
        structural_location: nullableText(hit.structural_location), bm25_score: nullableNumber(hit.bm25_score),
        vector_score: nullableNumber(hit.vector_score), fusion_score: number(hit.fusion_score),
        reranker_score: nullableNumber(hit.reranker_score), updated_at: text(hit.updated_at),
        integrity_sha256: text(hit.integrity_sha256),
      }
    }),
    citations: array(item.citations, (entry) => {
      const citation = record(entry)
      return {
        citation_id: text(citation.citation_id), knowledge_base_id: text(citation.knowledge_base_id),
        document_id: text(citation.document_id), document_version_id: text(citation.document_version_id),
        chunk_id: text(citation.chunk_id), document_title: text(citation.document_title),
        heading_path: array(citation.heading_path, text), page_number: nullableNumber(citation.page_number),
        structural_location: nullableText(citation.structural_location), excerpt: text(citation.excerpt),
        updated_at: text(citation.updated_at),
        integrity_sha256: text(citation.integrity_sha256), bm25_score: nullableNumber(citation.bm25_score),
        vector_score: nullableNumber(citation.vector_score), fusion_score: number(citation.fusion_score),
        reranker_score: nullableNumber(citation.reranker_score),
      }
    }),
    degradations: array(item.degradations, (entry) => {
      const degradation = record(entry)
      return {
        kind: text(degradation.kind) as RetrievalResult['degradations'][number]['kind'],
        error_category: text(degradation.error_category), message: text(degradation.message),
      }
    }),
  }
}

function evaluation(value: unknown): EvaluationSummary {
  const item = record(value)
  return {
    dataset_id: text(item.dataset_id), dataset_version: text(item.dataset_version),
    dataset_sha256: nullableText(item.dataset_sha256),
    case_count: number(item.case_count), metrics: Object.fromEntries(
      Object.entries(record(item.metrics)).map(([key, value]) => [key, number(value)]),
    ), thresholds: Object.fromEntries(
      Object.entries(record(item.thresholds)).map(([key, value]) => [key, number(value)]),
    ), case_results: array(item.case_results, (entry) => {
      const result = record(entry)
      return {
        case_id: text(result.case_id), language: text(result.language) as 'zh' | 'en',
        query: text(result.query),
        expected_document_ids: array(result.expected_document_ids, text),
        baseline_document_ids: array(result.baseline_document_ids, text),
        retrieved_document_ids: array(result.retrieved_document_ids, text),
        cited_document_ids: array(result.cited_document_ids, text),
        expected_refusal: boolean(result.expected_refusal),
        actual_refusal: boolean(result.actual_refusal),
        recall_at_k: nullableNumber(result.recall_at_k),
        reciprocal_rank: nullableNumber(result.reciprocal_rank),
        citation_precision: nullableNumber(result.citation_precision),
        expected_citation_recall: nullableNumber(result.expected_citation_recall),
        extractive_faithfulness: nullableNumber(result.extractive_faithfulness),
        latency_ms: number(result.latency_ms), failed_call_count: number(result.failed_call_count),
        passed: boolean(result.passed), failure_reasons: array(result.failure_reasons, text),
      }
    }), quality_gate_passed: boolean(item.quality_gate_passed),
  }
}

function curatedPackImport(value: unknown): CuratedPackImportSummary {
  const item = record(value)
  return {
    pack_id: text(item.pack_id),
    pack_version: text(item.pack_version),
    usage_policy: text(item.usage_policy),
    knowledge_base_id: text(item.knowledge_base_id),
    verified_at: text(item.verified_at),
    review_due_at: text(item.review_due_at),
    imported: array(item.imported, text),
    skipped: array(item.skipped, text),
  }
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException('Request aborted', 'AbortError')
}

async function request<T>(path: string, parse: (body: unknown) => T, init: RequestInit, callerSignal?: AbortSignal): Promise<T> {
  if (callerSignal?.aborted) throw abortReason(callerSignal)
  const controller = new AbortController()
  const onCallerAbort = () => controller.abort(abortReason(callerSignal as AbortSignal))
  callerSignal?.addEventListener('abort', onCallerAbort, { once: true })
  const timeout = window.setTimeout(
    () => controller.abort(new DOMException('Knowledge request timed out', 'TimeoutError')),
    REQUEST_TIMEOUT_MS,
  )
  try {
    const response = await fetch(`${API_ROOT}${path}`, { ...init, signal: controller.signal })
    let body: unknown
    try {
      body = await response.json()
    } catch {
      throw new KnowledgeApiError('知识库服务返回了无效响应', { status: response.status })
    }
    if (!response.ok) {
      try {
        const error = record(record(body).error)
        throw new KnowledgeApiError(text(error.message), {
          code: text(error.code), requestId: text(error.request_id), status: response.status,
        })
      } catch (error) {
        if (error instanceof KnowledgeApiError) throw error
        throw new KnowledgeApiError(`知识库请求失败（${response.status}）`, { status: response.status })
      }
    }
    try {
      return parse(body)
    } catch {
      throw new KnowledgeApiError('知识库服务返回了不符合契约的数据', { status: response.status })
    }
  } finally {
    window.clearTimeout(timeout)
    callerSignal?.removeEventListener('abort', onCallerAbort)
  }
}

const JSON_HEADERS = { 'Content-Type': 'application/json' }
const empty = () => undefined

export function listKnowledgeBases(signal?: AbortSignal): Promise<KnowledgeBase[]> {
  return request('/knowledge-bases', (body) => array(record(body).items, knowledgeBase), { method: 'GET' }, signal)
}

export function createKnowledgeBase(name: string, signal?: AbortSignal): Promise<KnowledgeBase> {
  return request('/knowledge-bases', knowledgeBase, {
    method: 'POST', headers: JSON_HEADERS,
    body: JSON.stringify({ name, default_sensitivity: 'internal', version_policy: 'immutable' }),
  }, signal)
}

export function importSecurityVerticalPack(signal?: AbortSignal): Promise<CuratedPackImportSummary> {
  return request('/knowledge-bases/imports/security-vertical', curatedPackImport, {
    method: 'POST', headers: JSON_HEADERS, body: '{}',
  }, signal)
}

export function deleteKnowledgeBase(knowledgeBaseId: string, signal?: AbortSignal): Promise<void> {
  return request(
    `/knowledge-bases/${encodeURIComponent(knowledgeBaseId)}`,
    empty,
    { method: 'DELETE' },
    signal,
  )
}

export function uploadDocument(knowledgeBaseId: string, file: File, signal?: AbortSignal): Promise<KnowledgeDocument> {
  const body = new FormData()
  body.append('file', file, file.name)
  body.append('sensitivity', 'internal')
  body.append('permission_tags', '')
  return request(`/knowledge-bases/${encodeURIComponent(knowledgeBaseId)}/documents`, document, { method: 'POST', body }, signal)
}

export function listDocuments(knowledgeBaseId: string, signal?: AbortSignal): Promise<KnowledgeDocument[]> {
  return request(`/knowledge-bases/${encodeURIComponent(knowledgeBaseId)}/documents`, (value) => array(record(value).items, document), { method: 'GET' }, signal)
}

export function listDocumentChunks(documentId: string, versionId: string, signal?: AbortSignal): Promise<KnowledgeChunk[]> {
  return request(
    `/documents/${encodeURIComponent(documentId)}/versions/${encodeURIComponent(versionId)}/chunks`,
    (value) => array(record(value).items, knowledgeChunk),
    { method: 'GET' },
    signal,
  )
}

export function listDocumentVersions(documentId: string, signal?: AbortSignal): Promise<KnowledgeDocument> {
  return request(`/documents/${encodeURIComponent(documentId)}/versions`, (value) => document(record(value).document), { method: 'GET' }, signal)
}

export function publishVersion(documentId: string, versionId: string, signal?: AbortSignal): Promise<void> {
  return request(`/documents/${encodeURIComponent(documentId)}/versions/${encodeURIComponent(versionId)}/publish`, empty, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, signal)
}

export function rollbackVersion(documentId: string, versionId: string, signal?: AbortSignal): Promise<void> {
  return request(`/documents/${encodeURIComponent(documentId)}/versions/${encodeURIComponent(versionId)}/rollback`, empty, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, signal)
}

export function deleteDocument(documentId: string, signal?: AbortSignal): Promise<void> {
  return request(`/documents/${encodeURIComponent(documentId)}`, empty, { method: 'DELETE' }, signal)
}

export function rebuildDocumentVersion(documentId: string, versionId: string, signal?: AbortSignal): Promise<void> {
  return request(`/documents/${encodeURIComponent(documentId)}/versions/${encodeURIComponent(versionId)}/rebuild`, empty, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, signal)
}

export function retrieveKnowledge(knowledgeBaseId: string, query: string, signal?: AbortSignal): Promise<RetrievalResult> {
  return request('/rag/retrieval', retrieval, {
    method: 'POST', headers: JSON_HEADERS,
    body: JSON.stringify({ knowledge_base_ids: [knowledgeBaseId], query, limit: 8 }),
  }, signal)
}

export function runEvaluation(knowledgeBaseId: string, signal?: AbortSignal): Promise<EvaluationSummary> {
  return request('/rag/evaluations', evaluation, {
    method: 'POST', headers: JSON_HEADERS,
    body: JSON.stringify({
      dataset_id: 'shieldchain-security-vertical-v1',
      knowledge_base_ids: [knowledgeBaseId],
      max_cases: 100,
    }),
  }, signal)
}
