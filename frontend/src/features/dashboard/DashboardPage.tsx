import { useEffect, useState } from 'react'

import { getLiveness } from '../../api/client'

type HealthState = 'loading' | 'healthy' | 'unavailable'

export function DashboardPage() {
  const [health, setHealth] = useState<HealthState>('loading')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    setHealth('loading')

    void getLiveness(controller.signal).then(
      () => setHealth('healthy'),
      () => {
        if (!controller.signal.aborted) {
          setHealth('unavailable')
        }
      },
    )

    return () => controller.abort()
  }, [attempt])

  return (
    <section aria-labelledby="dashboard-title" className="page-card dashboard-page">
      <p className="eyebrow">运营总览</p>
      <h2 id="dashboard-title">系统健康状态</h2>
      <div className={`health-state health-state--${health}`} role="status" aria-live="polite">
        {health === 'loading' && <p>正在检查系统状态</p>}
        {health === 'healthy' && <p>系统运行正常</p>}
        {health === 'unavailable' && (
          <div>
            <p>系统当前不可用</p>
            <button type="button" onClick={() => setAttempt((value) => value + 1)}>
              重试健康检查
            </button>
          </div>
        )}
      </div>
    </section>
  )
}
