import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AssistantPage } from './AssistantPage'

function jsonResponse(body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  }))
}

beforeEach(() => {
  vi.stubGlobal('confirm', vi.fn(() => true))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AssistantPage composer', () => {
  it('sends with Enter and keeps Shift+Enter for line breaks', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/assistant/chat')) {
        return jsonResponse({
          conversation_id: 'conversation-1',
          answer: '已收到。',
          model: 'deepseek-test',
          citations: [],
          memory_summary: '',
        })
      }
      if (url.endsWith('/assistant/conversations/conversation-1')) {
        return jsonResponse({
          id: 'conversation-1',
          title: '测试对话',
          created_at: '2026-08-09T00:00:00Z',
          updated_at: '2026-08-09T00:00:01Z',
          memory_summary: '',
          summary: '测试对话',
          pinned: false,
          message_count: 2,
          messages: [],
        })
      }
      void init
      return jsonResponse({ items: [] })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><AssistantPage /></MemoryRouter>)

    expect(screen.queryByRole('button', { name: '返回上一页' })).not.toBeInTheDocument()
    const composer = screen.getByPlaceholderText('询问 ShieldChain')
    await user.type(composer, '测试问题')
    fireEvent.keyDown(composer, { key: 'Enter', code: 'Enter', shiftKey: true })
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/assistant/chat'))).toHaveLength(0)

    fireEvent.keyDown(composer, { key: 'Enter', code: 'Enter' })
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/assistant/chat'))).toHaveLength(1))

    const chatCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/assistant/chat'))
    expect(JSON.parse(String(chatCall?.[1]?.body))).toMatchObject({ message: '测试问题' })
  })

  it('does not render grounding state or citation provenance', async () => {
    const conversation = {
      id: 'conversation-1', title: '引用测试', created_at: '2026-09-03T00:00:00Z',
      updated_at: '2026-09-03T00:00:01Z', memory_summary: '', summary: '引用测试',
      pinned: false, message_count: 1,
    }
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      void init
      const url = String(input)
      if (url.endsWith('/assistant/conversations/conversation-1')) {
        return jsonResponse({
          ...conversation,
          messages: [{
            id: 'message-1', role: 'assistant', content: '隔离前必须经过人工审批。',
            grounding_status: 'grounded', refusal_reason: null, degradations: [],
            model: 'deepseek-test', created_at: '2026-09-03T00:00:01Z',
            citations: [{
              index: 1, knowledge_base_id: 'base-1', document_id: 'document-1',
              document_version_id: 'version-1', chunk_id: 'chunk-1',
              document_title: '安全处置手册.md', excerpt: '隔离前必须经过人工审批。',
              heading_path: ['处置边界'], page_number: 3, structural_location: '第 3 页',
              fusion_score: 0.9, updated_at: '2026-09-03T00:00:00Z', integrity_sha256: 'a'.repeat(64),
              verified_at: '2026-09-02', review_due_at: '2026-10-02',
              source_tiers: ['primary_authority'], source_urls: ['https://www.cac.gov.cn/example'],
            }],
          }],
        })
      }
      return jsonResponse({ items: [conversation] })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><AssistantPage /></MemoryRouter>)
    await user.click(await screen.findByRole('button', { name: '引用测试' }))

    expect(await screen.findByText('隔离前必须经过人工审批。')).toBeVisible()
    expect(screen.queryByText('查看回答状态')).not.toBeInTheDocument()
    expect(screen.queryByText('有依据回答')).not.toBeInTheDocument()
    expect(screen.queryByText('引用证据（1）')).not.toBeInTheDocument()
    expect(screen.queryByText('[1] 安全处置手册.md')).not.toBeInTheDocument()
    expect(screen.getAllByText('隔离前必须经过人工审批。')).toHaveLength(1)
  })

  it('measures an overflowing conversation title for hover scrolling', async () => {
    const title = 'NTA隔离回放与ShieldChain脚本命令告警分析'
    vi.stubGlobal('fetch', vi.fn(() => jsonResponse({ items: [{
      id: 'conversation-long', title, summary: title, pinned: false, message_count: 1,
      created_at: '2026-09-09T00:00:00Z', updated_at: '2026-09-09T00:00:01Z', memory_summary: '',
    }] })))

    render(<MemoryRouter><AssistantPage /></MemoryRouter>)

    const openButton = await screen.findByRole('button', { name: title })
    const viewport = openButton.querySelector('.gemini-conversation-title-viewport') as HTMLElement
    const text = viewport.firstElementChild as HTMLElement
    Object.defineProperty(viewport, 'clientWidth', { configurable: true, value: 180 })
    Object.defineProperty(text, 'scrollWidth', { configurable: true, value: 260 })
    fireEvent.mouseEnter(viewport)

    expect(viewport).toHaveAttribute('data-overflow', 'true')
    expect(viewport.style.getPropertyValue('--conversation-title-scroll')).toBe('80px')
  })

  it('renders safe answer emphasis, lists, and inline code', async () => {
    const conversation = {
      id: 'conversation-markdown', title: '格式测试', summary: '格式测试', pinned: false, message_count: 1,
      created_at: '2026-09-09T00:00:00Z', updated_at: '2026-09-09T00:00:01Z', memory_summary: '',
    }
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => String(input).endsWith('/conversation-markdown')
      ? jsonResponse({ ...conversation, messages: [{
        id: 'message-markdown', role: 'assistant', content: '## 研判结论\n\n**高风险**，建议：\n\n- 隔离主机\n- 封禁 `198.51.100.7`',
        citations: [], model: 'deepseek-test', created_at: conversation.updated_at,
      }] })
      : jsonResponse({ items: [conversation] })))

    render(<MemoryRouter><AssistantPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: '格式测试' }))

    expect(await screen.findByRole('heading', { name: '研判结论' })).toBeVisible()
    expect(screen.getByText('高风险').tagName).toBe('STRONG')
    expect(screen.getByText('隔离主机').closest('li')).not.toBeNull()
    expect(screen.getByText('198.51.100.7').tagName).toBe('CODE')
  })

})
