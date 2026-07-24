import { NavLink, Outlet, useLocation } from 'react-router-dom'

import { useRunContext } from './RunContext'
import { RunContextSwitcher } from './RunContextSwitcher'

const navigation = [
  { label: '运营总览', short: '总', to: '/' },
  { label: '事件调查', short: '事', to: '/events' },
  { label: '智能体工作台', short: '智', to: '/agents' },
  { label: '知识库', short: '知', to: '/knowledge' },
  { label: '处置中心', short: '处', to: '/response' },
  { label: '报告与审计', short: '报', to: '/reports' },
]

export function App() {
  const location = useLocation()
  const context = useRunContext()
  const contextKey = `${context.incidentId ?? ''}:${context.runId ?? ''}`

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <header className="brand-bar">
        <div className="brand-bar__inner">
          <div className="brand-lockup">
            <span className="brand-mark" aria-hidden="true">盾</span>
            <div>
              <p className="brand-kicker">ShieldChain Security Operations</p>
              <h1>盾链智御</h1>
            </div>
          </div>
          <div className="environment-state" aria-label="当前运行环境">
            <span aria-hidden="true" />
            离线仿真环境
          </div>
        </div>
      </header>
      <div className="app-shell">
        <aside className="sidebar">
          <p className="sidebar__label">工作空间</p>
          <nav aria-label="主要导航">
            {navigation.map(({ label, short, to }) => (
              <NavLink key={to} to={{ pathname: to, search: location.search }} end={to === '/'}>
                <span className="nav-mark" aria-hidden="true">{short}</span>
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>
          <RunContextSwitcher />
          <div className="sidebar__boundary">
            <strong>安全边界</strong>
            <p>所有变更动作均经策略、审批与验证。</p>
          </div>
        </aside>
        <main className="content-panel" id="main-content" tabIndex={-1} key={contextKey}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
