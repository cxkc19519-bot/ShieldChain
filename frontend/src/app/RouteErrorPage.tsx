import { useEffect, useRef } from 'react'
import { isRouteErrorResponse, Link, useRouteError } from 'react-router-dom'

export function RouteErrorPage() {
  const error = useRouteError()
  const heading = useRef<HTMLHeadingElement>(null)
  const status = isRouteErrorResponse(error) ? error.status : null

  useEffect(() => heading.current?.focus(), [])

  return (
    <main className="route-error" aria-labelledby="route-error-title">
      <section className="page-card state-panel state-panel--error" role="alert">
        <span className="state-panel__mark" aria-hidden="true" />
        <div>
          <p className="eyebrow">安全失败关闭</p>
          <h1 id="route-error-title" ref={heading} tabIndex={-1}>页面暂时不可用</h1>
          <p>界面已停止渲染异常内容。请返回运营总览，或重新加载后再试。</p>
          {status && <p>公开状态码：{status}</p>}
          <div className="route-error__actions">
            <Link className="button" to="/">返回运营总览</Link>
            <button type="button" onClick={() => window.location.reload()}>重新加载</button>
          </div>
        </div>
      </section>
    </main>
  )
}
