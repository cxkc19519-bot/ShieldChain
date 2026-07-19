import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'

import {
  createKnowledgeBase,
  deleteDocument,
  listDocuments,
  listKnowledgeBases,
  publishVersion,
  rebuildDocumentVersion,
  retrieveKnowledge,
  rollbackVersion,
  runEvaluation,
  uploadDocument,
} from './api'
import type { EvaluationSummary, KnowledgeBase, KnowledgeDocument, RetrievalResult } from './types'
import './knowledge.css'

const ACCEPTED_EXTENSIONS = ['.pdf', '.docx', '.xlsx', '.csv', '.txt', '.md', '.html']
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : '操作失败，请稍后重试'
}

function Status({ value }: { value: string }) {
  const warning = ['failed', 'degraded', 'delete_pending'].includes(value)
  return <span className={`knowledge-status ${warning ? 'knowledge-status--warning' : ''}`}>{value}</span>
}

function Documents({
  documents,
  busy,
  onAction,
}: {
  documents: KnowledgeDocument[]
  busy: boolean
  onAction: (action: 'publish' | 'rollback' | 'rebuild' | 'delete', documentId: string, versionId?: string) => void
}) {
  if (documents.length === 0) return <p className="knowledge-empty">尚未上传文档。</p>
  return (
    <ul className="document-list">
      {documents.map((document) => (
        <li key={document.id}>
          <div className="document-heading">
            <div><strong>{document.original_filename}</strong><small>{document.media_type}</small></div>
            <div><Status value={document.status} /></div>
          </div>
          <div className="version-list">
            {document.versions.map((version) => (
              <article key={version.id} aria-label={`${document.original_filename} 版本 ${version.version_number}`}>
                <div>
                  <strong>v{version.version_number}</strong>
                  {version.id === document.current_version_id && <span className="current-version">当前版本</span>}
                  <Status value={version.index_status} />
                </div>
                {version.chunking_failure_category && <small>分块降级：{version.chunking_failure_category}</small>}
                <div className="compact-actions">
                  <button disabled={busy} type="button" onClick={() => onAction('publish', document.id, version.id)}>发布</button>
                  <button disabled={busy || version.id === document.current_version_id} type="button" onClick={() => onAction('rollback', document.id, version.id)}>回滚到此版本</button>
                  <button disabled={busy} type="button" onClick={() => onAction('rebuild', document.id, version.id)}>重建索引</button>
                </div>
              </article>
            ))}
          </div>
          <button className="danger-button" disabled={busy} type="button" onClick={() => onAction('delete', document.id)}>删除文档</button>
        </li>
      ))}
    </ul>
  )
}

function SearchResult({ result }: { result: RetrievalResult }) {
  return (
    <section className="search-result" aria-labelledby="retrieval-result-title">
      <h3 id="retrieval-result-title">检索结果</h3>
      {result.degradations.length > 0 && (
        <div className="degradation" role="status">{result.degradations.map((item) => <p key={item.kind}>检索降级 · {item.kind}/{item.error_category}：{item.message}</p>)}</div>
      )}
      {result.refusal_reason ? (
        <div className="refusal" role="alert">
          <strong>已拒绝生成无依据答案 · {result.refusal_reason}</strong>
          <p>当前证据不满足安全回答条件，请补充或核验证据后重试。</p>
        </div>
      ) : <p className="answer">{result.answer}</p>}
      <p><small>查询：{result.query}</small></p>
      {result.hits.length > 0 && <ol className="citation-list" aria-label="混合召回结果">{result.hits.map((hit) => (
        <li key={hit.chunk_id}>
          <strong>{hit.document_title} · 融合 {hit.fusion_score.toFixed(4)}</strong>
          <p>{hit.excerpt}</p>
          <small>{hit.heading_path.join(' / ') || hit.structural_location || '未标注位置'}{hit.page_number ? ` · 第 ${hit.page_number} 页` : ''}</small>
          <dl className="score-grid"><dt>BM25</dt><dd>{hit.bm25_score ?? '不可用'}</dd><dt>向量</dt><dd>{hit.vector_score ?? '不可用'}</dd><dt>重排</dt><dd>{hit.reranker_score ?? '不可用'}</dd></dl>
        </li>
      ))}</ol>}
      {result.citations.length > 0 && (
        <ol className="citation-list">
          {result.citations.map((citation) => (
            <li key={citation.citation_id}>
              <details>
                <summary>{citation.document_title} · {citation.heading_path.join(' / ') || citation.structural_location || '未标注位置'}</summary>
                <p>{citation.excerpt}</p>
                <dl className="score-grid">
                  <dt>文档版本</dt><dd>{citation.document_version_id}</dd>
                  <dt>页码</dt><dd>{citation.page_number ?? '—'}</dd>
                  <dt>内容块</dt><dd>{citation.chunk_id}</dd>
                  <dt>BM25</dt><dd>{citation.bm25_score ?? '不可用'}</dd>
                  <dt>向量</dt><dd>{citation.vector_score ?? '不可用'}</dd>
                  <dt>融合</dt><dd>{citation.fusion_score}</dd>
                  <dt>重排</dt><dd>{citation.reranker_score ?? '不可用'}</dd>
                  <dt>完整性摘要</dt><dd><code>{citation.integrity_sha256}</code></dd>
                </dl>
              </details>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}

function Evaluation({ summary }: { summary: EvaluationSummary }) {
  return (
    <section aria-labelledby="evaluation-title" className="evaluation-summary">
      <h3 id="evaluation-title">评测摘要</h3>
      <p><strong>{summary.dataset_id}</strong> · {summary.dataset_version} · {summary.case_count} 条</p>
      <p className={`quality-gate ${summary.quality_gate_passed ? '' : 'quality-gate--failed'}`}>{summary.quality_gate_passed ? '质量门禁通过' : '质量门禁未通过'}</p>
      <dl className="metric-grid">{Object.entries(summary.metrics).map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value.toFixed(3)}</dd></div>)}</dl>
    </section>
  )
}

export function KnowledgePage() {
  const [bases, setBases] = useState<KnowledgeBase[]>([])
  const [documents, setDocuments] = useState<Record<string, KnowledgeDocument[]>>({})
  const [selectedId, setSelectedId] = useState('')
  const [query, setQuery] = useState('')
  const [newBaseName, setNewBaseName] = useState('')
  const [result, setResult] = useState<RetrievalResult | null>(null)
  const [evaluation, setEvaluation] = useState<EvaluationSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const activeRequest = useRef<AbortController | null>(null)

  const load = useCallback(async (signal?: AbortSignal) => {
    const response = await listKnowledgeBases(signal)
    setBases(response)
    const documentLists = await Promise.all(response.map(async (base) => [base.id, await listDocuments(base.id, signal)] as const))
    setDocuments(Object.fromEntries(documentLists))
    setSelectedId((current) => response.some((item) => item.id === current) ? current : response[0]?.id ?? '')
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal).catch((reason: unknown) => {
      if (!controller.signal.aborted) setError(errorMessage(reason))
    })
    return () => {
      controller.abort()
      activeRequest.current?.abort()
    }
  }, [load])

  const execute = async (operation: (signal: AbortSignal) => Promise<void>, success: string) => {
    activeRequest.current?.abort()
    const controller = new AbortController()
    activeRequest.current = controller
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      await operation(controller.signal)
      await load(controller.signal)
      setNotice(success)
    } catch (reason) {
      if (!controller.signal.aborted) setError(errorMessage(reason))
    } finally {
      if (activeRequest.current === controller) activeRequest.current = null
      setBusy(false)
    }
  }

  const handleUpload = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const file = form.get('file')
    if (!(file instanceof File) || file.size === 0) {
      setError('请选择一个非空文档')
      return
    }
    const lowerName = file.name.toLowerCase()
    if (!ACCEPTED_EXTENSIONS.some((extension) => lowerName.endsWith(extension)) || file.size > MAX_UPLOAD_BYTES) {
      setError('仅支持 PDF、DOCX、XLSX、CSV、TXT、Markdown、HTML，且文件不得超过 20 MB')
      return
    }
    const formElement = event.currentTarget
    void execute(async (signal) => {
      const uploaded = await uploadDocument(selectedId, file, signal)
      setDocuments((current) => ({ ...current, [selectedId]: [uploaded, ...(current[selectedId] ?? []).filter((item) => item.id !== uploaded.id)] }))
      formElement.reset()
    }, '文档已安全上传，正在处理与索引')
  }

  const handleAction = (action: 'publish' | 'rollback' | 'rebuild' | 'delete', documentId: string, versionId?: string) => {
    if (action === 'delete' && !window.confirm('确认删除此文档及其索引？该操作不可撤销。')) return
    void execute(async (signal) => {
      if (action === 'delete') await deleteDocument(documentId, signal)
      else if (action === 'publish') await publishVersion(documentId, versionId as string, signal)
      else if (action === 'rollback') await rollbackVersion(documentId, versionId as string, signal)
      else await rebuildDocumentVersion(documentId, versionId as string, signal)
    }, action === 'delete' ? '文档删除任务已提交' : '版本操作已提交')
  }

  const selected = bases.find((item) => item.id === selectedId)

  return (
    <section aria-labelledby="knowledge-title" className="page-card knowledge-page">
      <p className="eyebrow">可信知识与检索</p>
      <h2 id="knowledge-title">知识库</h2>

      {error && <p className="knowledge-message knowledge-message--error" role="alert">{error}</p>}
      {notice && <p className="knowledge-message" role="status">{notice}</p>}

      <div className="knowledge-layout">
        <aside className="knowledge-bases" aria-label="知识库列表">
          <h3>知识库</h3>
          <form className="create-base" onSubmit={(event) => {
            event.preventDefault()
            const name = newBaseName.trim()
            if (!name) return
            void execute(async (signal) => {
              const created = await createKnowledgeBase(name, signal)
              setSelectedId(created.id)
              setNewBaseName('')
            }, '知识库已创建')
          }}>
            <label className="sr-only" htmlFor="new-knowledge-base">新知识库名称</label>
            <input id="new-knowledge-base" maxLength={200} value={newBaseName} onChange={(event) => setNewBaseName(event.target.value)} placeholder="新知识库名称" />
            <button disabled={busy || newBaseName.trim().length === 0} type="submit">创建</button>
          </form>
          {bases.length === 0 ? <p>暂无可用知识库</p> : bases.map((base) => (
            <button key={base.id} type="button" aria-pressed={base.id === selectedId} onClick={() => setSelectedId(base.id)}>
              <strong>{base.name}</strong><span>{documents[base.id]?.length ?? 0} 个文档</span>
            </button>
          ))}
        </aside>

        <div className="knowledge-workspace">
          {selected ? <>
            <header className="workspace-header">
              <div><h3>{selected.name}</h3><p>{selected.status} · {selected.default_sensitivity} · {selected.version_policy}</p></div>
              <button disabled={busy} type="button" onClick={() => void execute(async (signal) => {
                const summary = await runEvaluation(selected.id, signal)
                setEvaluation(summary)
              }, '固定基准评测已完成')}>运行评测</button>
            </header>

            <form className="upload-panel" onSubmit={handleUpload}>
              <label htmlFor="knowledge-file">上传本地文档</label>
              <p>只读取你选择的文件；不接受本机路径或远程 URL。</p>
              <input id="knowledge-file" name="file" type="file" required accept={ACCEPTED_EXTENSIONS.join(',')} />
              <button disabled={busy} type="submit">上传并索引</button>
            </form>

            <section aria-labelledby="documents-title">
              <h3 id="documents-title">文档与版本</h3>
              <Documents documents={documents[selected.id] ?? []} busy={busy} onAction={handleAction} />
            </section>

            <form className="search-panel" onSubmit={(event) => {
              event.preventDefault()
              const normalized = query.trim()
              if (!normalized) return
              void execute(async (signal) => {
                setResult(await retrieveKnowledge(selected.id, normalized, signal))
              }, '检索完成')
            }}>
              <label htmlFor="knowledge-query">检索知识库</label>
              <div><input id="knowledge-query" value={query} maxLength={2_000} onChange={(event) => setQuery(event.target.value)} placeholder="输入安全运营问题" />
                <button disabled={busy || query.trim().length === 0} type="submit">混合检索</button></div>
            </form>
            {result && <SearchResult result={result} />}
            {evaluation && <Evaluation summary={evaluation} />}
          </> : <p>请选择知识库。</p>}
        </div>
      </div>
    </section>
  )
}
