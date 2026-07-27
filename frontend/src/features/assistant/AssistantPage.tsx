import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowUp, History, MessageSquarePlus, Search, Trash2 } from 'lucide-react'

import logoUrl from '../../assets/logo.png'
import './assistant.css'

type Citation = { index: number; document_title: string; excerpt: string; fusion_score: number }
type Message = { id: string; role: 'user' | 'assistant'; content: string; citations: Citation[]; model: string | null; created_at: string }
type Conversation = { id: string; title: string; created_at: string; updated_at: string; memory_summary: string; summary: string; message_count: number }
type Detail = Conversation & { messages: Message[] }
const API_ROOT = '/api/v1'
const starters = ['最近一次调查报告的研判结论是什么？', '总结历史报告中尚未完成的验证。', '钓鱼邮件事件应该如何处置？']

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, init)
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const message = typeof body === 'object' && body !== null && 'error' in body && typeof (body as { error?: { message?: unknown } }).error?.message === 'string'
      ? String((body as { error: { message: string } }).error.message) : `请求失败（${response.status}）`
    throw new Error(message)
  }
  return body as T
}

function dateLabel(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric' })
}

export function AssistantPage() {
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [active, setActive] = useState<Detail | null>(null)
  const [draft, setDraft] = useState('')
  const [search, setSearch] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const textarea = useRef<HTMLTextAreaElement>(null)

  const filtered = useMemo(() => conversations.filter((item) => item.title.includes(search.trim())), [conversations, search])
  const refreshList = () => api<{ items: Conversation[] }>('/assistant/conversations').then((result) => setConversations(result.items))

  useEffect(() => { void refreshList().catch((reason) => setError(reason instanceof Error ? reason.message : '无法加载本地对话')) }, [])

  async function openConversation(id: string) {
    setError(null)
    try { setActive(await api<Detail>(`/assistant/conversations/${encodeURIComponent(id)}`)) } catch (reason) { setError(reason instanceof Error ? reason.message : '无法打开对话') }
  }

  function newConversation() {
    setActive(null); setDraft(''); setError(null); window.setTimeout(() => textarea.current?.focus(), 0)
  }

  async function send(event?: FormEvent, starter?: string) {
    event?.preventDefault()
    const message = (starter ?? draft).trim()
    if (!message || pending) return
    setDraft(''); setPending(true); setError(null)
    const optimistic: Message = { id: `pending-${Date.now()}`, role: 'user', content: message, citations: [], model: null, created_at: new Date().toISOString() }
    setActive((current) => current ? { ...current, messages: [...current.messages, optimistic] } : { id: '', title: message.slice(0, 32), created_at: optimistic.created_at, updated_at: optimistic.created_at, memory_summary: '正在建立本地记忆…', summary: '正在生成摘要…', message_count: 1, messages: [optimistic] })
    try {
      const result = await api<{ conversation_id: string; answer: string; model: string | null; citations: Citation[]; memory_summary: string }>('/assistant/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message, conversation_id: active?.id || null }),
      })
      const detail = await api<Detail>(`/assistant/conversations/${encodeURIComponent(result.conversation_id)}`)
      setActive(detail); await refreshList()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '智能助手暂时不可用')
      setActive((current) => current ? { ...current, messages: current.messages.filter((item) => item.id !== optimistic.id) } : null)
    } finally { setPending(false); window.setTimeout(() => textarea.current?.focus(), 0) }
  }

  async function deleteConversation(event: React.MouseEvent, id: string) {
    event.stopPropagation()
    if (!window.confirm('删除这段本地聊天记录及其记忆摘要？此操作无法恢复。')) return
    try {
      await api<void>(`/assistant/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (active?.id === id) newConversation()
      await refreshList()
    } catch (reason) { setError(reason instanceof Error ? reason.message : '删除失败') }
  }

  const empty = !active || active.messages.length === 0
  return <section className="gemini-page" aria-label="ShieldChain 智能助手">
    <aside className="gemini-sidebar">
      <div className="gemini-brand"><Link to="/" aria-label="返回主页"><span className="gemini-star"><img src={logoUrl} alt="ShieldChain" /></span><strong>ShieldChain</strong></Link></div>
      <button type="button" className="gemini-new" onClick={newConversation}><MessageSquarePlus size={18} />发起新对话</button>
      <label className="gemini-search"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索对话内容" /></label>
      <div className="gemini-section-title"><History size={15} />最近</div>
      <nav className="gemini-conversations" aria-label="本地聊天记录">{filtered.length ? filtered.map((item) => <button className={active?.id === item.id ? 'active' : ''} type="button" onClick={() => void openConversation(item.id)} key={item.id}><span><b>{item.title}</b><small>{item.summary}</small></span><i onClick={(event) => void deleteConversation(event, item.id)} aria-label={`删除 ${item.title}`} title="删除记录"><Trash2 size={15} /></i></button>) : <p>暂无本地对话</p>}</nav>
      
    </aside>
    <main className={`gemini-main ${empty ? 'gemini-main--empty' : ''}`}>
      <Link className="gemini-home-link" to="/">主页</Link>
      {empty ? <div className="gemini-welcome"><div className="gemini-orb"><img src={logoUrl} alt="ShieldChain" /></div><h1><span>你好，</span>有什么安全问题想聊聊？</h1><div className="gemini-suggestions">{starters.map((item) => <button type="button" onClick={() => void send(undefined, item)} disabled={pending} key={item}>{item}</button>)}</div></div> : <div className="gemini-thread">{active.messages.map((item) => <article className={`gemini-message gemini-message--${item.role}`} key={item.id}><div><p>{item.content}</p></div></article>)}{pending && <article className="gemini-message gemini-message--assistant"><p className="gemini-loading"><i /><i /><i />思考中…</p></article>}</div>}
      {error && <p className="gemini-error" role="alert">{error}</p>}
      <form className="gemini-composer" onSubmit={(event) => void send(event)}><textarea ref={textarea} value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="询问 ShieldChain" rows={1} maxLength={4096} /><button type="submit" disabled={!draft.trim() || pending} aria-label="发送"><ArrowUp size={19} strokeWidth={2.8} /></button></form>
      <p className="gemini-disclaimer">回答基于本地知识库与历史报告，仅供研判参考；不会执行任何处置操作。</p>
    </main>
  </section>
}
