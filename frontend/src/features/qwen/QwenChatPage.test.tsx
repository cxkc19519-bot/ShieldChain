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
      if (url.endsWith('/models')) {
        return jsonResponse({
          ready: true,
          active_model: 'qwen3', phase: 'ready', can_switch: true, message: '模型已就绪',
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

    await waitFor(() => expect(screen.getByRole('textbox', { name: '给 Qwen 发送消息' })).toBeEnabled())
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
      model: 'qwen3',
    })
  })

  it('selects the downloaded model, queues its startup and disables chat until ready', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => jsonResponse(String(input).endsWith('/select')
      ? { ready: false, active_model: 'qwen3', phase: 'queued', can_switch: true, message: '已排队' }
      : { ready: true, active_model: 'qwen3', phase: 'ready', can_switch: true, message: '模型已就绪' }))
    vi.stubGlobal('fetch', fetchMock)
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const user = userEvent.setup()
    render(<MemoryRouter><QwenChatPage /></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('textbox')).toBeEnabled())
    await user.selectOptions(screen.getByLabelText('测试模型'), 'qwen38')
    expect(screen.getByRole('textbox')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '启动所选模型' }))
    expect(await screen.findByRole('button', { name: '正在切换…' })).toBeDisabled()
    expect(fetchMock).toHaveBeenLastCalledWith('/api/v1/qwen/select', expect.objectContaining({ body: JSON.stringify({ model: 'qwen38' }) }))
    expect(screen.getByLabelText('测试模型')).toBeDisabled()
    vi.restoreAllMocks()
  })

  it('keeps histories separate and disables input when status is unavailable', async () => {
    localStorage.setItem('shieldchain-qwen-experience-v1-qwen3', JSON.stringify([{ id: '1', role: 'user', content: '旧模型的问题' }]))
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))))
    const user = userEvent.setup()
    render(<MemoryRouter><QwenChatPage /></MemoryRouter>)
    expect(screen.getByText('旧模型的问题')).toBeVisible()
    await user.selectOptions(screen.getByLabelText('测试模型'), 'qwen38')
    expect(screen.queryByText('旧模型的问题')).not.toBeInTheDocument()
    expect(screen.getByRole('textbox')).toBeDisabled()
    expect(screen.getByRole('button', { name: '启动所选模型' })).toBeDisabled()
    await user.selectOptions(screen.getByLabelText('测试模型'), 'qwen3')
    expect(screen.getByText('旧模型的问题')).toBeVisible()
  })
})
