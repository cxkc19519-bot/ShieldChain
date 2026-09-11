import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { useRouteFocus } from './useRouteFocus'

function FocusTarget({ pathname }: { pathname: string }) {
  const target = useRouteFocus(pathname)
  return <main ref={target} tabIndex={-1}>主要内容</main>
}

describe('useRouteFocus', () => {
  it('keeps initial focus and moves it after the pathname changes', () => {
    const view = render(<FocusTarget pathname="/" />)
    const main = screen.getByRole('main')
    expect(main).not.toHaveFocus()

    view.rerender(<FocusTarget pathname="/reports" />)
    expect(main).toHaveFocus()
  })
})
