import { Activity, Search, AlertTriangle, Database, FileText, Home, Briefcase, HelpCircle, MessageCircle, Sparkles, Bot, ShieldCheck, Server } from 'lucide-react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

import logoUrl from '../assets/logo.png'
import { useRunContext } from './RunContext'
import { useRouteFocus } from './useRouteFocus'

const navigation = [
  { label: '运营总览', icon: Activity, to: '/dashboard' },
  { label: '安全运营报告', icon: Search, to: '/operations-report' },
  { label: '智能体与 ReAct', icon: Bot, to: '/agents' },
  { label: '处置中心', icon: ShieldCheck, to: '/response' },
  { label: '实时告警', icon: AlertTriangle, to: '/alerts' },
  { label: '知识库', icon: Database, to: '/knowledge' },
  { label: '历史报告', icon: FileText, to: '/reports' },
  { label: '智能助手', icon: MessageCircle, to: '/assistant' },
  { label: '模型测试', icon: Sparkles, to: '/qwen-chat' },
  { label: 'MCP 服务状态', icon: Server, to: '/status' },
]

export function App() {
  const location = useLocation()
  const context = useRunContext()
  const contextKey = `${context.incidentId ?? ''}:${context.runId ?? ''}`

  const main = useRouteFocus(location.pathname)
  const isAssistant = location.pathname === '/assistant' || location.pathname === '/qwen-chat'

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      {!isAssistant && <header className="brand-bar">
        <div className="brand-bar__inner">
          <div className="brand-lockup">
            <span className="brand-mark" aria-hidden="true">
              <img src={logoUrl} alt="logo" style={{ width: '28px', height: '28px', display: 'block' }} />
            </span>
            <div>
              <h1 style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>ShieldChain</h1>
            </div>
          </div>
          <nav className="top-nav" aria-label="主要导航">
            <NavLink to="/" className="top-nav-item" end>
              <Home className="nav-icon" aria-hidden="true" size={20} strokeWidth={2.5} />
              <span>主页</span>
            </NavLink>
            <div className="nav-dropdown-container">
              <button type="button" className="top-nav-item nav-dropdown-trigger">
                <Briefcase className="nav-icon" aria-hidden="true" size={20} strokeWidth={2.5} />
                <span>工作区</span>
              </button>
              <div className="nav-dropdown-menu">
                {navigation.map(({ label, icon: Icon, to }) => (
                  <NavLink key={to} to={{ pathname: to, search: location.search }}>
                    <Icon className="nav-icon" aria-hidden="true" size={18} strokeWidth={2.5} />
                    <span>{label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
            <NavLink to="/help" className="top-nav-item">
              <HelpCircle className="nav-icon" aria-hidden="true" size={20} strokeWidth={2.5} />
              <span>帮助</span>
            </NavLink>
          </nav>
          <div className="environment-state" aria-label="当前运行环境">
            <span aria-hidden="true" />
            真实数据分析环境
          </div>
        </div>
      </header>}
      <main id="main-content" tabIndex={-1} key={contextKey} ref={main}>
        {isAssistant ? <Outlet /> : ['/', '/help', '/about', '/status', '/changelog'].includes(location.pathname) ? (
          <Outlet />
        ) : (
          <div className="app-shell app-shell--single">
            <div className="content-panel">
              <Outlet />
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
