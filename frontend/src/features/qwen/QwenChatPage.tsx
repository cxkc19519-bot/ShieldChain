import { FormEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowUp, Bot, Cpu, Eraser, Gauge, Home, RotateCcw, SlidersHorizontal, Sparkles } from 'lucide-react'
import { Link } from 'react-router-dom'

import logoUrl from '../../assets/logo.png'
import './qwen-chat.css'

type Role = 'user' | 'assistant'
type Message = { id: string; role: Role; content: string; model?: string; tokens?: number }
type Status = { ready: boolean; model: string; provider: 'local-qwen' | 'configured-openai-compatible' }
type ChatResponse = { content: string; model: string; prompt_tokens: number; completion_tokens: number }

const API_ROOT = '/api/v1/qwen'
const STORAGE_KEY = 'shieldchain-qwen-experience-v1'
const suggestions = [
  '用通俗语言解释零信任安全模型。',
  '帮我设计一套 Windows 终端安全排查流程。',
  '比较 Wazuh、Zeek 和 Suricata 的职责。',
]

function displayContent(message: Message): string {
  if (message.role === 'user') return message.content
  return message.content
    .replace(/^\s{0,3}#{1,6}\s+/gm, '')
    .replace(/\*\*/g, '')
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, init)
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const message = typeof body === 'object' && body !== null && 'error' in body
      && typeof (body as { error?: { message?: unknown } }).error?.message === 'string'
      ? String((body as { error: { message: string } }).error.message)
      : `请求失败（${response.status}）`
    throw new Error(message)
  }
  return body as T
}

function restoreMessages(): Message[] {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]')
    if (!Array.isArray(raw)) return []
    const restored = raw.filter((item): item is Message => {
      if (!item || typeof item !== 'object') return false
      const value = item as Partial<Message>
      return (value.role === 'user' || value.role === 'assistant')
        && typeof value.content === 'string' && value.content.trim().length > 0
    }).slice(-20)
    return restored.every((item, index) => index === 0
      ? item.role === 'user'
      : item.role !== restored[index - 1].role) ? restored : []
  } catch {
    return []
  }
}

export function QwenChatPage() {
  const [messages, setMessages] = useState<Message[]>(restoreMessages)
  const [draft, setDraft] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [temperature, setTemperature] = useState(0.7)
  const [maxTokens, setMaxTokens] = useState(1024)
  const textarea = useRef<HTMLTextAreaElement>(null)
  const threadEnd = useRef<HTMLDivElement>(null)

  const totalTokens = useMemo(
    () => messages.reduce((total, message) => total + (message.tokens || 0), 0),
    [messages],
  )

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages))
    if (typeof threadEnd.current?.scrollIntoView === 'function') {
      threadEnd.current.scrollIntoView({ behavior: 'smooth', block: 'end' })
    }
  }, [messages, pending])

  useEffect(() => {
    void api<Status>('/status').then(setStatus).catch(() => setStatus(null))
  }, [])

  async function send(event?: FormEvent, suggested?: string) {
    event?.preventDefault()
    const content = (suggested ?? draft).trim()
    if (!content || pending || status?.ready === false) return
    const userMessage: Message = { id: crypto.randomUUID(), role: 'user', content }
    const nextMessages = [...messages, userMessage].slice(-19)
    setMessages(nextMessages)
    setDraft('')
    setPending(true)
    setError(null)
    try {
      const result = await api<ChatResponse>('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: nextMessages.map(({ role, content: messageContent }) => ({ role, content: messageContent })),
          temperature,
          max_tokens: maxTokens,
        }),
      })
      setMessages((current) => [...current, {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: result.content,
        model: result.model,
        tokens: result.completion_tokens,
      }])
    } catch (reason) {
      setMessages((current) => current.filter((message) => message.id !== userMessage.id))
      setError(reason instanceof Error ? reason.message : 'Qwen 暂时无法回答')
    } finally {
      setPending(false)
      window.setTimeout(() => textarea.current?.focus(), 0)
    }
  }

  function clearConversation() {
    if (messages.length > 0 && !window.confirm('清空当前 Qwen 对话？此操作无法恢复。')) return
    setMessages([])
    setError(null)
    setDraft('')
    window.setTimeout(() => textarea.current?.focus(), 0)
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      void send()
    }
  }

  return (
    <div className="qwen-lab">
      <aside className="qwen-panel">
        <div className="qwen-brand">
          <img src={logoUrl} alt="ShieldChain" />
          <div><b>ShieldChain</b><span>模型实验室</span></div>
        </div>
        <Link className="qwen-home" to="/"><Home size={18} />返回主页</Link>

        <section className="qwen-model-card">
          <div className="qwen-model-icon"><Cpu size={22} /></div>
          <div>
            <span>当前模型</span>
            <strong>{status?.model || 'Qwen3-30B-A3B'}</strong>
          </div>
          <i className={status?.ready ? 'online' : 'offline'} />
        </section>
        <p className="qwen-status-text">
          {status?.ready ? '本地模型已就绪' : status ? '模型服务未就绪' : '正在检查模型状态…'}
        </p>

        <section className="qwen-settings">
          <h2><SlidersHorizontal size={17} />生成参数</h2>
          <label>
            <span>温度 <b>{temperature.toFixed(1)}</b></span>
            <input type="range" min="0" max="1.5" step="0.1" value={temperature}
              onChange={(event) => setTemperature(Number(event.target.value))} />
            <small>数值越高，回答越有创造性</small>
          </label>
          <label>
            <span>最大输出</span>
            <select value={maxTokens} onChange={(event) => setMaxTokens(Number(event.target.value))}>
              <option value={512}>512 tokens</option>
              <option value={1024}>1024 tokens</option>
              <option value={2048}>2048 tokens</option>
            </select>
          </label>
        </section>

        <div className="qwen-stats">
          <Gauge size={17} /><span>本轮已生成</span><b>{totalTokens} tokens</b>
        </div>
        <button className="qwen-clear" type="button" onClick={clearConversation} disabled={pending}>
          <Eraser size={17} />清空对话
        </button>
      </aside>

      <main className="qwen-stage">
        <header className="qwen-header">
          <div><span>本地大模型体验</span><h1>Qwen 30B 对话</h1></div>
          <div className="qwen-direct"><span />直连服务器模型</div>
        </header>

        {messages.length === 0 ? (
          <section className="qwen-welcome">
            <div className="qwen-orb"><Bot size={34} /></div>
            <p><Sparkles size={16} />Qwen3-30B-A3B-Instruct-2507-FP8</p>
            <h2>想测试什么能力？</h2>
            <span>这里不经过知识库检索，直接体验基础模型的多轮对话能力。</span>
            <div className="qwen-suggestions">
              {suggestions.map((suggestion) => (
                <button type="button" key={suggestion} onClick={() => void send(undefined, suggestion)}
                  disabled={pending || status?.ready === false}>{suggestion}</button>
              ))}
            </div>
          </section>
        ) : (
          <section className="qwen-thread" aria-live="polite">
            {messages.map((message) => (
              <article className={`qwen-message qwen-message--${message.role}`} key={message.id}>
                <div className="qwen-message-body">
                  <p>{displayContent(message)}</p>
                  {message.role === 'assistant' && <small>{message.model}{message.tokens ? ` · ${message.tokens} tokens` : ''}</small>}
                </div>
              </article>
            ))}
            {pending && <article className="qwen-message qwen-message--assistant">
              <div className="qwen-thinking"><i /><i /><i /><span>思考中</span></div>
            </article>}
            <div ref={threadEnd} />
          </section>
        )}

        <div className="qwen-composer-wrap">
          {error && <div className="qwen-error"><span>{error}</span><button type="button" onClick={() => setError(null)}><RotateCcw size={15} />关闭</button></div>}
          <form className="qwen-composer" onSubmit={(event) => void send(event)}>
            <textarea ref={textarea} value={draft} onChange={(event) => setDraft(event.target.value)}
              onKeyDown={handleKeyDown} rows={1} maxLength={8000} placeholder="给 Qwen 发送消息"
              disabled={pending || status?.ready === false} aria-label="给 Qwen 发送消息" />
            <button type="submit" disabled={!draft.trim() || pending || status?.ready === false} aria-label="发送">
              <ArrowUp size={20} />
            </button>
          </form>
          <p>内容由 AI 生成，请注意甄别。Enter 发送，Shift + Enter 换行。</p>
        </div>
      </main>
    </div>
  )
}
