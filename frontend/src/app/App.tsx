import { NavLink, Outlet } from 'react-router-dom'

const navigation = [
  { label: '运营总览', to: '/' },
  { label: '事件调查', to: '/events' },
  { label: '智能体工作台', to: '/agents' },
  { label: '知识库', to: '/knowledge' },
  { label: '处置中心', to: '/response' },
  { label: '报告与审计', to: '/reports' },
]

export function App() {
  return (
    <div className="app-frame">
      <header className="brand-bar">
        <p className="brand-kicker">安全运营中心</p>
        <h1>盾链智御</h1>
      </header>
      <div className="app-shell">
        <aside className="sidebar">
          <nav aria-label="主要导航">
            {navigation.map(({ label, to }) => (
              <NavLink key={to} to={to} end={to === '/'}>
                {label}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="content-panel">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
