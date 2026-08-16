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
})