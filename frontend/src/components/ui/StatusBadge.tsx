import type { ReactNode } from 'react'

type StatusTone = 'neutral' | 'info' | 'success' | 'warning' | 'danger'

export function StatusBadge({ children, tone = 'neutral' }: { children: ReactNode; tone?: StatusTone }) {
  return <span className={`status-badge status-badge--${tone}`}>{children}</span>
}
