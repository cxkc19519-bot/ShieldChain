import { FormEvent, Fragment, KeyboardEvent, MouseEvent as ReactMouseEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowUp, Check, Copy, History, MessageSquarePlus, PanelLeft, PanelLeftClose, PanelLeftOpen, MoreVertical, Pencil, Pin, PinOff, Search, Trash2, X } from 'lucide-react'

import logoUrl from '../../assets/logo.png'
import './assistant.css'

type Citation = {
  index: number
  knowledge_base_id: string | null
  document_id: string | null
  document_version_id: string | null
  chunk_id: string | null
  document_title: string
  excerpt: string
  heading_path: string[]
  page_number: number | null
  structural_location: string | null
  fusion_score: number
  updated_at: string | null
  integrity_sha256: string | null
  verified_at: string | null
  review_due_at: string | null
  source_tiers: string[]
  source_urls: string[]
}
type Degradation = { kind: string; error_category: string; message: string }
type Message = {
  id: string
  role: 'user' | 'assistant'
  content: string
  citations: Citation[]
  grounding_status?: 'not_applicable' | 'conversational' | 'model_knowledge' | 'grounded' | 'extractive_degraded' | 'refused' | 'legacy'
  refusal_reason?: string | null
  degradations?: Degradation[]
  model: string | null
  created_at: string
}
type Conversation = { id: string; title: string; created_at: string; updated_at: string; memory_summary: string; summary: string; pinned: boolean; message_count: number }
type Detail = Conversation & { messages: Message[] }
const API_ROOT = '/api/v1'
const starters = ['总结这一周的安全运营报告', '最近有哪些高风险安全事件？', '钓鱼邮件事件应该如何处置？']

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

function renderInlineMarkdown(value: string): ReactNode[] {
  return value.split(/(\*\*[^*\n]+\*\*|__[^_\n]+__|`[^`\n]+`)/g).filter(Boolean).map((part, index) => {
    if ((part.startsWith('**') && part.endsWith('**')) || (part.startsWith('__') && part.endsWith('__'))) {
      return <strong key={index}>{part.slice(2, -2)}</strong>
    }
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>
    return <Fragment key={index}>{part}</Fragment>
  })
}

function renderListItemMarkdown(value: string): ReactNode {
  if (/^(\*\*|__)/.test(value)) return renderInlineMarkdown(value)
  const labeled = /^([^：:]{2,18})([：:])\s*(.+)$/.exec(value)
  if (!labeled) return renderInlineMarkdown(value)
  return <><strong>{labeled[1]}</strong>{labeled[2]} {renderInlineMarkdown(labeled[3])}</>
}

function AssistantMarkdown({ content }: { content: string }) {
  const lines = content.trim().split(/\r?\n/)
  const blocks: ReactNode[] = []
  const isBlockStart = (line: string) => /^(#{1,3}\s+|[-*]\s+|\d+\.\s+|>\s*)/.test(line)
  let cursor = 0

  while (cursor < lines.length) {
    const line = lines[cursor].trim()
    if (!line) { cursor += 1; continue }
    const heading = /^(#{1,3})\s+(.+)$/.exec(line)
    if (heading) {
      const text = renderInlineMarkdown(heading[2])
      blocks.push(heading[1].length === 1 ? <h2 key={cursor}>{text}</h2> : heading[1].length === 2 ? <h3 key={cursor}>{text}</h3> : <h4 key={cursor}>{text}</h4>)
      cursor += 1
      continue
    }
    if (/^[-*]\s+/.test(line)) {
      const items: ReactNode[] = []
      while (cursor < lines.length && /^[-*]\s+/.test(lines[cursor].trim())) {
        items.push(<li key={cursor}>{renderListItemMarkdown(lines[cursor].trim().replace(/^[-*]\s+/, ''))}</li>)
        cursor += 1
      }
      blocks.push(<ul key={`ul-${cursor}`}>{items}</ul>)
      continue
    }
    if (/^\d+\.\s+/.test(line)) {
      const items: ReactNode[] = []
      while (cursor < lines.length && /^\d+\.\s+/.test(lines[cursor].trim())) {
        items.push(<li key={cursor}>{renderListItemMarkdown(lines[cursor].trim().replace(/^\d+\.\s+/, ''))}</li>)
        cursor += 1
      }
      blocks.push(<ol key={`ol-${cursor}`}>{items}</ol>)
      continue
    }
    if (/^>\s*/.test(line)) {
      blocks.push(<blockquote key={cursor}>{renderInlineMarkdown(line.replace(/^>\s*/, ''))}</blockquote>)
      cursor += 1
      continue
    }
    const paragraph: string[] = []
    while (cursor < lines.length && lines[cursor].trim() && !isBlockStart(lines[cursor].trim())) {
      paragraph.push(lines[cursor].trim())
      cursor += 1
    }
    blocks.push(<p key={`p-${cursor}`}>{paragraph.map((text, index) => <Fragment key={index}>{index > 0 && <br />}{renderInlineMarkdown(text)}</Fragment>)}</p>)
  }
  return <div className="gemini-message-content">{blocks}</div>
}

function prepareConversationTitleScroll(event: ReactMouseEvent<HTMLSpanElement>) {
  const viewport = event.currentTarget
  const title = viewport.firstElementChild as HTMLElement | null
  if (!title) return
  const distance = Math.max(0, title.scrollWidth - viewport.clientWidth)
  viewport.dataset.overflow = distance > 0 ? 'true' : 'false'
  viewport.style.setProperty('--conversation-title-scroll', `${distance}px`)
}

export function AssistantPage() {
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [active, setActive] = useState<Detail | null>(null)
  const [draft, setDraft] = useState('')
  const [search, setSearch] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [sidebarToggleHovered, setSidebarToggleHovered] = useState(false)
  const [openMenuId, setOpenMenuId] = useState<string | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null)
  const textarea = useRef<HTMLTextAreaElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const threadRef = useRef<HTMLDivElement>(null)

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

  useEffect(() => {
    const thread = threadRef.current
    if (thread) thread.scrollTop = thread.scrollHeight
  }, [active?.id, active?.messages.length, pending])

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

  function handleComposerKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== 'Enter' || event.shiftKey || event.nativeEvent.isComposing) return
    event.preventDefault()
    void send()
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
  async function copyMessage(item: Message) {
    try {
      await navigator.clipboard.writeText(item.content)
      setCopiedMessageId(item.id)
      window.setTimeout(() => setCopiedMessageId((current) => current === item.id ? null : current), 1600)
    } catch {
      setError('复制失败，请手动选择文字。')
    }
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
              <span className="gemini-conversation-label">{item.pinned && <Pin className="gemini-pin-mark" size={13} />}<span className="gemini-conversation-title-viewport" onMouseEnter={prepareConversationTitleScroll}><b>{item.summary || item.title}</b></span></span>
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
      {empty ? <div className="gemini-welcome"><div className="gemini-orb"><img src={logoUrl} alt="ShieldChain" /></div><h1><span>你好，</span>有什么安全问题想聊聊？</h1><div className="gemini-suggestions">{starters.map((item) => <button type="button" onClick={() => void send(undefined, item)} disabled={pending} key={item}>{item}</button>)}</div></div> : <div className="gemini-thread" ref={threadRef}>{active.messages.map((item) => <article className={`gemini-message gemini-message--${item.role}`} key={item.id}><div className="gemini-message-stack">
        <div className="gemini-message-bubble">
          {item.role === 'assistant' ? <AssistantMarkdown content={item.content} /> : <p>{item.content}</p>}
          {item.role === 'assistant' && Boolean(item.degradations?.length) && <div className="gemini-degradations" role="status">{item.degradations?.map((entry) => <p key={`${entry.kind}-${entry.error_category}-${entry.message}`}>{entry.kind}/{entry.error_category}：{entry.message}</p>)}</div>}
        </div>
        <button className="gemini-copy-message" type="button" onClick={() => void copyMessage(item)} aria-label={item.role === 'assistant' ? '复制助手回复' : '复制用户消息'} title={copiedMessageId === item.id ? '已复制' : '复制'}>{copiedMessageId === item.id ? <Check size={16} /> : <Copy size={16} />}</button>
      </div></article>)}{pending && <article className="gemini-message gemini-message--assistant"><p className="gemini-loading"><i /><i /><i />思考中…</p></article>}</div>}
      {error && <p className="gemini-error" role="alert">{error}</p>}
      <form className="gemini-composer" onSubmit={(event) => void send(event)}><textarea ref={textarea} value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={handleComposerKeyDown} placeholder="询问 ShieldChain" rows={1} maxLength={4096} /><button type="submit" disabled={!draft.trim() || pending} aria-label="发送"><ArrowUp size={19} strokeWidth={2.8} /></button></form>
      <p className="gemini-disclaimer">内容由 AI 回复，请注意甄别。</p>
      </>}
    </main>
  </section>
}
