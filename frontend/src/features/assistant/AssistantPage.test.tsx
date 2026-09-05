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
          model: 'qwen',
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
            model: 'local-qwen', created_at: '2026-09-03T00:00:01Z',
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

  it('runs and displays the fixed assistant evaluation', async () => {
    const evaluation = {
      dataset_id: 'shieldchain-assistant-v1', dataset_version: '1.0.0',
      dataset_sha256: 'b'.repeat(64), case_count: 1,
      metrics: { status_accuracy: 1, case_pass_rate: 1 },
      thresholds: { status_accuracy: 0.875, case_pass_rate: 0.75 },
      quality_gate_passed: true,
      case_results: [{
        case_id: 'zh-greeting', language: 'zh', message: '你好',
        expected_statuses: ['conversational'], actual_status: 'conversational',
        expected_refusal_reason: null, actual_refusal_reason: null,
        expected_document_ids: [], cited_document_ids: [], citation_recall: null,
        provenance_completeness: null, latency_ms: 2, passed: true,
        failure_reasons: [],
      }],
    }
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      void init
      const url = String(input)
      if (url.endsWith('/assistant/evaluations')) return jsonResponse(evaluation)
      return jsonResponse({ items: [] })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    render(<MemoryRouter><AssistantPage /></MemoryRouter>)

    await user.click(screen.getByRole('button', { name: '运行助手固定评测' }))

    expect(await screen.findByText('质量门禁通过')).toBeVisible()
    expect(screen.getByText(/shieldchain-assistant-v1/)).toBeVisible()
    expect(screen.getByText(/zh-greeting/)).toBeVisible()
    const request = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/assistant/evaluations'))
    expect(JSON.parse(String(request?.[1]?.body))).toEqual({
      dataset_id: 'shieldchain-assistant-v1', max_cases: 100,
    })
  })
})
