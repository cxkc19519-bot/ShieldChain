import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { appRoutes } from './router'

const getLivenessMock = vi.hoisted(() => vi.fn())

vi.mock('../api/client', () => ({
  getLiveness: getLivenessMock,
}))

function renderRoute(path = '/') {
  const router = createMemoryRouter(appRoutes, { initialEntries: [path] })
  return render(<RouterProvider router={router} />)
}

beforeEach(() => {
  getLivenessMock.mockReset()
})

describe('application shell', () => {
  it('renders the product identity, navigation, and semantic landmarks', async () => {
    getLivenessMock.mockResolvedValue({ status: 'ok' })
    renderRoute()

    expect(screen.getByRole('banner')).toHaveTextContent('盾链智御')
    expect(screen.getByRole('navigation', { name: '主要导航' })).toBeInTheDocument()
    expect(screen.getByRole('main')).toBeInTheDocument()

    for (const name of ['运营总览', '事件调查', '智能体工作台', '知识库', '处置中心', '报告与审计']) {
      expect(screen.getByRole('link', { name })).toBeVisible()
    }

    expect(await screen.findByText('系统运行正常')).toBeVisible()
  })

  it('supports keyboard navigation through visible links', async () => {
    getLivenessMock.mockResolvedValue({ status: 'ok' })
    const user = userEvent.setup()
    renderRoute()

    await user.tab()
    expect(screen.getByRole('link', { name: '运营总览' })).toHaveFocus()
    await user.tab()
    expect(screen.getByRole('link', { name: '事件调查' })).toHaveFocus()
  })
})

describe('dashboard health', () => {
  it('shows loading before a successful health result', async () => {
    let resolveHealth: ((value: { status: 'ok' }) => void) | undefined
    getLivenessMock.mockReturnValue(
      new Promise((resolve) => {
        resolveHealth = resolve
      }),
    )
    renderRoute()

    expect(screen.getByText('正在检查系统状态')).toBeVisible()
    resolveHealth?.({ status: 'ok' })
    expect(await screen.findByText('系统运行正常')).toBeVisible()
  })

  it('shows an unavailable state and retries without claiming health', async () => {
    getLivenessMock.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ status: 'ok' })
    const user = userEvent.setup()
    renderRoute()

    expect(await screen.findByText('系统当前不可用')).toBeVisible()
    expect(screen.queryByText('系统运行正常')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '重试健康检查' }))

    expect(await screen.findByText('系统运行正常')).toBeVisible()
    expect(getLivenessMock).toHaveBeenCalledTimes(2)
  })

  it('cancels an in-flight health request when the dashboard unmounts', async () => {
    getLivenessMock.mockReturnValue(new Promise(() => undefined))
    const view = renderRoute()

    await waitFor(() => expect(getLivenessMock).toHaveBeenCalledOnce())
    const signal = getLivenessMock.mock.calls[0]?.[0] as AbortSignal
    expect(signal.aborted).toBe(false)

    view.unmount()
    expect(signal.aborted).toBe(true)
  })
})

describe('future routes', () => {
  it.each(['/reports'])(
    'marks %s as not implemented',
    (path) => {
      renderRoute(path)

      expect(screen.getByText('尚未进入该开发阶段')).toBeVisible()
      expect(getLivenessMock).not.toHaveBeenCalled()
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    },
  )

  it('renders the trusted tool control center at /response', () => {
    renderRoute('/response')

    expect(screen.getByRole('heading', { name: '处置中心', level: 2 })).toBeVisible()
    expect(screen.getByText(/不展示原始结果/)).toBeVisible()
    expect(screen.queryByText('尚未进入该开发阶段')).not.toBeInTheDocument()
  })

  it('renders the read-only agents workbench at /agents', () => {
    renderRoute('/agents')

    expect(screen.getByRole('heading', { name: '智能体工作台', level: 2 })).toBeVisible()
    expect(screen.getByText(/不展示私有上下文/)).toBeVisible()
    expect(screen.queryByText('尚未进入该开发阶段')).not.toBeInTheDocument()
  })

  it('renders the knowledge page at /knowledge', () => {
    renderRoute('/knowledge')

    expect(screen.getByRole('heading', { name: '知识库', level: 2 })).toBeVisible()
    expect(screen.queryByText('尚未进入该开发阶段')).not.toBeInTheDocument()
  })

  it('renders the investigation page at /events', () => {
    renderRoute('/events')

    expect(screen.getByRole('heading', { name: '事件调查' })).toBeVisible()
    expect(screen.getByText('模拟环境')).toBeVisible()
    expect(screen.queryByText('尚未进入该开发阶段')).not.toBeInTheDocument()
  })
})
