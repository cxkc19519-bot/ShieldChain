import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { QwenChatPage } from './QwenChatPage'

function jsonResponse(body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  }))
}

beforeEach(() => {
  localStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('QwenChatPage', () => {
  it('shows the local model status and completes a direct multi-turn request', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      void init
      const url = String(input)
      if (url.endsWith('/status')) {
        return jsonResponse({
          ready: true,
          model: 'shieldchain-qwen3-30b',
          provider: 'local-qwen',
        })
      }
      return jsonResponse({
        content: '### 测试标题\n**Qwen 直接回答成功。**',
        model: 'shieldchain-qwen3-30b',
        prompt_tokens: 20,
        completion_tokens: 9,
      })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><QwenChatPage /></MemoryRouter>)

    expect(await screen.findByText('本地模型已就绪')).toBeVisible()
    await user.type(screen.getByRole('textbox', { name: '给 Qwen 发送消息' }), '介绍你的模型。')
    await user.click(screen.getByRole('button', { name: '发送' }))

    expect(await screen.findByText(/测试标题\s+Qwen 直接回答成功。/)).toBeVisible()
    expect(screen.queryByText(/\*\*|###/)).not.toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    const chatCall = fetchMock.mock.calls[1]
    expect(chatCall[0]).toBe('/api/v1/qwen/chat')
    const init = chatCall[1] as RequestInit
    expect(JSON.parse(String(init.body))).toMatchObject({
      messages: [{ role: 'user', content: '介绍你的模型。' }],
      temperature: 0.7,
      max_tokens: 1024,
    })
  })
})
