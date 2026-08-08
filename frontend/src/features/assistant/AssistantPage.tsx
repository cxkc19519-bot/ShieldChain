import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowUp, History, MessageSquarePlus, PanelLeft, PanelLeftClose, PanelLeftOpen, MoreVertical, Pencil, Pin, PinOff, Search, Trash2, X } from 'lucide-react'

import logoUrl from '../../assets/logo.png'
import './assistant.css'

type Citation = { index: number; document_title: string; excerpt: string; fusion_score: number }
type Message = { id: string; role: 'user' | 'assistant'; content: string; citations: Citation[]; model: string | null; created_at: string }
type Conversation = { id: string; title: string; created_at: string; updated_at: string; memory_summary: string; summary: string; pinned: boolean; message_count: number }
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
  if (Number.isNaN(date.getTime())) return ''
  const now = new Date()
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const target = new Date(date.getFullYear(), date.getMonth(), date.getDate())
  const diff = (today.getTime() - target.getTime()) / 86400000
  if (diff === 0) return '今天'
  if (diff === 1) return '昨天'
  return date.toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric' })
}

function displayAssistantText(content: string) {
  return content
    .replace(/\*\*/g, '')
    .replace(/__/g, '')
    .replace(/\[(?:\d+\s*(?:,\s*\d+\s*)*)\]/g, '')
    .trim()
}
export function AssistantPage() {
  const [conversations, setConversations] = useState<Conversation[]>([])
  const navigate = useNavigate()
  const [active, setActive] = useState<Detail | null>(null)
  const [draft, setDraft] = useState('')
  const [search, setSearch] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [sidebarToggleHovered, setSidebarToggleHovered] = useState(false)
  const [openMenuId, setOpenMenuId] = useState<string | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const textarea = useRef<HTMLTextAreaElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)

  const filtered = useMemo(() => conversations.filter((item) => item.title.includes(search.trim())), [conversations, search])
  const refreshList = () => api<{ items: Conversation[] }>('/assistant/conversations').then((result) => setConversations(result.items))

  useEffect(() => { void refreshList().catch((reason) => setError(reason instanceof Error ? reason.message : '无法加载本地对话')) }, [])

  useEffect(() => {
    if (!openMenuId) return
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setOpenMenuId(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [openMenuId])

  useEffect(() => {
    if (!searchOpen) return
    window.setTimeout(() => searchInputRef.current?.focus(), 50)
  }, [searchOpen])

  async function openConversation(id: string) {
    setSearchOpen(false)
    setSearch('')
    setOpenMenuId(null)
    setError(null)
    try { setActive(await api<Detail>(`/assistant/conversations/${encodeURIComponent(id)}`)) } catch (reason) { setError(reason instanceof Error ? reason.message : '无法打开对话') }
  }

  function newConversation() {
    setSearchOpen(false)
    setSearch('')
    setOpenMenuId(null)
    setActive(null); setDraft(''); setError(null); window.setTimeout(() => textarea.current?.focus(), 0)
  }

  async function send(event?: FormEvent, starter?: string) {
    event?.preventDefault()
    const message = (starter ?? draft).trim()
    if (!message || pending) return
    setDraft(''); setPending(true); setError(null)
    const optimistic: Message = { id: `pending-${Date.now()}`, role: 'user', content: message, citations: [], model: null, created_at: new Date().toISOString() }
    setActive((current) => current ? { ...current, messages: [...current.messages, optimistic] } : { id: '', title: message.slice(0, 32), created_at: optimistic.created_at, updated_at: optimistic.created_at, memory_summary: '正在建立本地记忆…', summary: '正在生成摘要…', pinned: false, message_count: 1, messages: [optimistic] })
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

  async function deleteConversation(id: string) {
    if (!window.confirm('删除这段本地聊天记录及其记忆摘要？此操作无法恢复。')) return
    try {
      await api<void>(`/assistant/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (active?.id === id) newConversation()
      await refreshList()
    } catch (reason) { setError(reason instanceof Error ? reason.message : '删除失败') }
  }
  async function setPinned(item: Conversation) {
    try {
      const updated = await api<Conversation>(`/assistant/conversations/${encodeURIComponent(item.id)}/pin`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pinned: !item.pinned }),
      })
      setConversations((current) => current.map((row) => row.id === item.id ? updated : row))
      setActive((current) => current?.id === item.id ? { ...current, ...updated } : current)
      setOpenMenuId(null)
      await refreshList()
    } catch (reason) { setError(reason instanceof Error ? reason.message : '\u56fa\u5b9a\u5bf9\u8bdd\u5931\u8d25') }
  }

  async function renameConversation(item: Conversation) {
    const nextTitle = window.prompt('\u91cd\u547d\u540d\u5bf9\u8bdd', item.title)?.replace(/\s+/g, ' ').trim()
    if (!nextTitle || nextTitle === item.title) return
    try {
      const updated = await api<Conversation>(`/assistant/conversations/${encodeURIComponent(item.id)}/title`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: nextTitle }),
      })
      setConversations((current) => current.map((row) => row.id === item.id ? updated : row))
      setActive((current) => current?.id === item.id ? { ...current, ...updated } : current)
      setOpenMenuId(null)
      await refreshList()
    } catch (reason) { setError(reason instanceof Error ? reason.message : '\u91cd\u547d\u540d\u5931\u8d25') }
  }

  const empty = !active || active.messages.length === 0
  function handleLogoClick() {
    if (sidebarCollapsed) { setSidebarCollapsed(false) } else { newConversation() }
  }
  function handleSearchItemClick(id: string) {
    setSearchOpen(false); setSearch(''); void openConversation(id)
  }
  return <section className={`gemini-page ${sidebarCollapsed ? 'gemini-page--sidebar-collapsed' : ''}`} aria-label="ShieldChain 智能助手">
    <aside className={`gemini-sidebar ${searchOpen ? 'gemini-sidebar--searching' : empty ? 'gemini-sidebar--new' : ''}`}>
      <div className="gemini-brand"><button type="button" className="gemini-brand-btn" onClick={handleLogoClick} aria-label={sidebarCollapsed ? '展开侧边栏' : '发起新对话'} title={sidebarCollapsed ? '展开侧边栏' : '发起新对话'}><span className="gemini-star"><img src={logoUrl} alt="ShieldChain" /></span><strong>ShieldChain</strong></button><button type="button" className="gemini-sidebar-toggle" onClick={() => setSidebarCollapsed((value) => !value)} onMouseEnter={() => setSidebarToggleHovered(true)} onMouseLeave={() => setSidebarToggleHovered(false)} onFocus={() => setSidebarToggleHovered(true)} onBlur={() => setSidebarToggleHovered(false)} aria-label="收起侧边栏" title="收起侧边栏" data-tooltip="关闭边栏">{sidebarCollapsed ? <PanelLeftOpen size={18} /> : sidebarToggleHovered ? <PanelLeftClose size={18} /> : <PanelLeft size={18} />}</button></div>
      <button type="button" className="gemini-new" onClick={newConversation}><MessageSquarePlus size={18} /><span>发起新对话</span></button>
      <button type="button" className="gemini-search-trigger" onClick={() => setSearchOpen(true)} aria-label="搜索对话内容" title="搜索对话内容"><Search size={17} /><span>搜索对话内容</span></button>
      <div className="gemini-section-title"><History size={15} /><span>最近</span></div>
      <nav className="gemini-conversations" aria-label="本地聊天记录">
        {filtered.length ? filtered.map((item) => (
          <div className={!searchOpen && active?.id === item.id ? 'gemini-conversation-item active' : 'gemini-conversation-item'} key={item.id}>
            <button className="gemini-conversation-open" type="button" onClick={() => void openConversation(item.id)}>
              <span>{item.pinned && <Pin className="gemini-pin-mark" size={13} />}<b>{item.summary || item.title}</b></span>
            </button>
            <div className="gemini-conversation-actions" ref={openMenuId === item.id ? menuRef : undefined}>
              <button className="gemini-conversation-more" type="button" onClick={() => setOpenMenuId((current) => current === item.id ? null : item.id)} aria-label={`对话操作 ${item.title}`} title="对话操作"><MoreVertical size={17} /></button>
              {openMenuId === item.id && <div className="gemini-conversation-menu" role="menu">
                <button type="button" onClick={() => void setPinned(item)} role="menuitem">{item.pinned ? <PinOff size={16} /> : <Pin size={16} />}<span>{item.pinned ? '取消固定' : '固定'}</span></button>
                <button type="button" onClick={() => void renameConversation(item)} role="menuitem"><Pencil size={16} /><span>重命名</span></button>
                <button className="danger" type="button" onClick={() => void deleteConversation(item.id)} role="menuitem"><Trash2 size={16} /><span>删除</span></button>
              </div>}
            </div>
          </div>
        )) : <p>暂无本地对话</p>}
      </nav>
      <button type="button" className="gemini-sidebar-toggle gemini-sidebar-toggle--expand" onClick={() => setSidebarCollapsed(false)} aria-label="展开侧边栏" title="展开侧边栏"><PanelLeftOpen size={18} /></button>
    </aside>
    <main className={`gemini-main ${empty && !searchOpen ? 'gemini-main--empty' : ''}`}>
      <button type="button" className="gemini-home-link" onClick={() => navigate(-1)} aria-label="返回上一页" title="返回上一页"><ArrowLeft size={20} /></button>
      {searchOpen ? <div className="gemini-search-view">
        <div className="gemini-search-bar">
          <Search size={18} />
          <input ref={searchInputRef} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索对话内容" autoFocus />
          <button type="button" onClick={() => { setSearchOpen(false); setSearch('') }} aria-label="关闭搜索"><X size={18} /></button>
        </div>
        <div className="gemini-search-results">
          <div className="gemini-search-results-title">结果</div>
          {filtered.length ? filtered.map((item) => (
            <button type="button" className="gemini-search-result" key={item.id} onClick={() => handleSearchItemClick(item.id)}>
              <div className="gemini-search-result-info">
                <span className="gemini-search-result-title">{item.title}</span>
                <span className="gemini-search-result-desc">{item.summary || item.memory_summary || ''}</span>
              </div>
              <span className="gemini-search-result-date">{dateLabel(item.updated_at || item.created_at)}</span>
            </button>
          )) : <p className="gemini-search-empty">没有找到匹配的对话</p>}
        </div>
      </div> : <>
      {empty ? <div className="gemini-welcome"><div className="gemini-orb"><img src={logoUrl} alt="ShieldChain" /></div><h1><span>你好，</span>有什么安全问题想聊聊？</h1><div className="gemini-suggestions">{starters.map((item) => <button type="button" onClick={() => void send(undefined, item)} disabled={pending} key={item}>{item}</button>)}</div></div> : <div className="gemini-thread">{active.messages.map((item) => <article className={`gemini-message gemini-message--${item.role}`} key={item.id}><div><p>{displayAssistantText(item.content)}</p></div></article>)}{pending && <article className="gemini-message gemini-message--assistant"><p className="gemini-loading"><i /><i /><i />思考中…</p></article>}</div>}
      {error && <p className="gemini-error" role="alert">{error}</p>}
      <form className="gemini-composer" onSubmit={(event) => void send(event)}><textarea ref={textarea} value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="询问 ShieldChain" rows={1} maxLength={4096} /><button type="submit" disabled={!draft.trim() || pending} aria-label="发送"><ArrowUp size={19} strokeWidth={2.8} /></button></form>
      <p className="gemini-disclaimer">内容由 AI 回复，请注意甄别。</p>
      </>}
    </main>
  </section>
}
