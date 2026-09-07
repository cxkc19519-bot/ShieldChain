export type Sensitivity = 'public' | 'internal' | 'confidential' | 'restricted'
export type DegradationKind = 'rewrite_degraded' | 'vector_degraded' | 'reranker_degraded'

export interface KnowledgeBase {
  id: string
  name: string
  status: 'draft' | 'published' | 'archived' | 'deleted'
  default_sensitivity: Sensitivity
  version_policy: string
  created_at: string
  updated_at: string
}

export interface KnowledgeVersion {
  id: string
  document_id: string
  version_number: number
  parsing_status: 'pending' | 'processing' | 'succeeded' | 'failed' | 'ocr_required'
  chunking_status: 'pending' | 'processing' | 'succeeded' | 'failed'
  index_status: 'pending' | 'processing' | 'succeeded' | 'failed' | 'delete_pending' | 'deleted'
  chunking_strategy: string
  chunking_failure_category: string | null
  created_at: string
  published_at: string | null
}

export interface KnowledgeDocument {
  id: string
  knowledge_base_id: string
  original_filename: string
  media_type: string
  status: 'draft' | 'published' | 'delete_pending' | 'deleted'
  current_version_id: string | null
  created_at: string
  updated_at: string
  versions: KnowledgeVersion[]
}

export interface KnowledgeChunk {
  id: string
  ordinal: number
  offset: number
  length: number
  text: string
  integrity_sha256: string
}

export interface RetrievalResult {
  query: string
  answer: string | null
  refusal_reason: 'insufficient_evidence' | 'conflicting_evidence' | 'stale_evidence' | 'unauthorized' | 'unsafe_content' | null
  hits: Array<{
    chunk_id: string
    knowledge_base_id: string
    document_id: string
    document_version_id: string
    document_title: string
    excerpt: string
    heading_path: string[]
    page_number: number | null
    structural_location: string | null
    bm25_score: number | null
    vector_score: number | null
    fusion_score: number
    reranker_score: number | null
    updated_at: string
    integrity_sha256: string
  }>
  citations: Array<{
    citation_id: string
    knowledge_base_id: string
    document_id: string
    document_version_id: string
    chunk_id: string
    document_title: string
    heading_path: string[]
    page_number: number | null
    structural_location: string | null
    excerpt: string
    updated_at: string
    integrity_sha256: string
    bm25_score: number | null
    vector_score: number | null
    fusion_score: number
    reranker_score: number | null
  }>
  degradations: Array<{ kind: DegradationKind; error_category: string; message: string }>
}

export interface EvaluationCaseResult {
  case_id: string
  language: 'zh' | 'en'
  query: string
  expected_document_ids: string[]
  baseline_document_ids: string[]
  retrieved_document_ids: string[]
  cited_document_ids: string[]
  expected_refusal: boolean
  actual_refusal: boolean
  recall_at_k: number | null
  reciprocal_rank: number | null
  citation_precision: number | null
  expected_citation_recall: number | null
  extractive_faithfulness: number | null
  latency_ms: number
  failed_call_count: number
  passed: boolean
  failure_reasons: string[]
}

export interface EvaluationSummary {
  dataset_id: string
  dataset_version: string
  dataset_sha256: string | null
  case_count: number
  metrics: Record<string, number>
  thresholds: Record<string, number>
  case_results: EvaluationCaseResult[]
  quality_gate_passed: boolean
}

export interface CuratedPackImportSummary {
  pack_id: string
  pack_version: string
  usage_policy: string
  knowledge_base_id: string
  verified_at: string
  review_due_at: string
  imported: string[]
  skipped: string[]
}
