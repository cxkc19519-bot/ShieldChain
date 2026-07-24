import type { ReactNode } from 'react'

interface StateProps {
  title: string
  detail?: string
  action?: ReactNode
}

function StatePanel({ kind, title, detail, action }: StateProps & { kind: string }) {
  const role = kind === 'error' ? 'alert' : 'status'
  return (
    <div className={`state-panel state-panel--${kind}`} role={role} aria-live="polite">
      <span className="state-panel__mark" aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        {detail && <p>{detail}</p>}
        {action && <div className="state-panel__action">{action}</div>}
      </div>
    </div>
  )
}

export function LoadingState({ title = '正在加载', detail }: Partial<StateProps>) {
  return <StatePanel kind="loading" title={title} detail={detail} />
}

export function EmptyState({ title, detail, action }: StateProps) {
  return <StatePanel kind="empty" title={title} detail={detail} action={action} />
}

export function ErrorState({ title, detail, action }: StateProps) {
  return <StatePanel kind="error" title={title} detail={detail} action={action} />
}
