import { render, screen } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { RouteErrorPage } from './RouteErrorPage'

afterEach(() => vi.restoreAllMocks())
function BrokenPage(): never {
  throw new Error('token=secret raw_prompt=private')
}


describe('RouteErrorPage', () => {
  it('fails closed without rendering private exception material', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const router = createMemoryRouter([{
      path: '/',
      element: <BrokenPage />,
      errorElement: <RouteErrorPage />,
    }])
    render(<RouterProvider router={router} />)

    const title = await screen.findByRole('heading', { name: '页面暂时不可用' })
    expect(title).toHaveFocus()
    expect(screen.getByRole('alert')).toBeVisible()
    expect(screen.queryByText(/token=secret|raw_prompt=private/)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '返回运营总览' })).toHaveAttribute('href', '/')
  })
})
