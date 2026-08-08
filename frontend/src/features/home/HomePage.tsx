import { Link } from 'react-router-dom'
import { Activity, ShieldCheck, Cpu, Library } from 'lucide-react'
import './home.css'

export function HomePage() {
  return (
    <div className="home-page">
      <div className="home-hero">
        <h1 className="home-title">
          下一代大模型驱动的<br />
          <span className="text-gradient">安全运营分析中枢</span>
        </h1>
        <p className="home-subtitle">
          ShieldChain 融合了前沿的 ReAct 多智能体协同技术与可信工具执行沙箱，为您提供从安全告警到自动化处置的端到端闭环运营体验。
        </p>
        <div className="home-actions">
          <Link to="/dashboard" className="button button-primary button-large">
            进入工作区
          </Link>
          <Link to="/operations-report" className="button button-secondary button-large">
            生成运营报告
          </Link>
        </div>
      </div>

      <section className="home-features">
        <div className="feature-card">
          <div className="feature-icon"><Activity size={28} /></div>
          <h3>真实数据分析</h3>
          <p>自动收集多源异构情报，还原攻击链路与证据，无需人工干预即可形成准确的安全研判。</p>
        </div>
        <div className="feature-card">
          <div className="feature-icon"><Cpu size={28} /></div>
          <h3>多智能体协同</h3>
          <p>依托超级智能体编排，基于预算控制的 ReAct 循环，各专业智能体无缝交接，高效协作。</p>
        </div>
        <div className="feature-card">
          <div className="feature-icon"><ShieldCheck size={28} /></div>
          <h3>受控建议与复核</h3>
          <p>内置沙箱审批机制，可信执行隔离与封禁等防御动作，并自动核验处置结果，确保威胁消除。</p>
        </div>
        <div className="feature-card">
          <div className="feature-icon"><Library size={28} /></div>
          <h3>知识驱动体系</h3>
          <p>通过 RAG 技术沉淀安全运营经验，让系统不断学习企业专属安全策略，越用越聪明。</p>
        </div>
      </section>

      <footer className="home-footer">
        <div className="footer-content">
          <div className="footer-links">
            <Link to="/about">关于我们</Link>
            <Link to="/status">服务状态</Link>
            <Link to="/changelog">更新日志</Link>
          </div>
          <div className="footer-copyright">
            <p>© 2026 ShieldChain. 保留所有权利</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
