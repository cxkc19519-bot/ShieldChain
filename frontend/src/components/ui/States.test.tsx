import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { EmptyState, ErrorState, LoadingState } from './States'
import { StatusBadge } from './StatusBadge'

describe('shared interface states', () => {
  it('announces loading and empty states without claiming success', () => {
    const { rerender } = render(<LoadingState title="正在加载案件" />)
    expect(screen.getByRole('status')).toHaveTextContent('正在加载案件')

    rerender(<EmptyState title="暂无案件" detail="启动调查后将在此显示。" />)
    expect(screen.getByRole('status')).toHaveTextContent('暂无案件')
    expect(screen.queryByText('已完成')).not.toBeInTheDocument()
  })

  it('uses an alert landmark for failures and text for badge meaning', () => {
    render(<><ErrorState title="加载失败" detail="请稍后重试。" /><StatusBadge tone="danger">需要复核</StatusBadge></>)
    expect(screen.getByRole('alert')).toHaveTextContent('加载失败')
    expect(screen.getByText('需要复核')).toHaveClass('status-badge--danger')
  })
})
