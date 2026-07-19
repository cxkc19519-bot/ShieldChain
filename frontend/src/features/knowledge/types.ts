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

export interface EvaluationSummary {
  dataset_id: string
  dataset_version: string
  case_count: number
  metrics: Record<string, number>
  quality_gate_passed: boolean
}
