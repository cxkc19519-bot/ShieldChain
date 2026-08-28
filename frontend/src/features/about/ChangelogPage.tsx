import React from 'react'
import { FileCode, GitCommit, Rocket } from 'lucide-react'

export function ChangelogPage() {
  return (
    <div style={{ maxWidth: '800px', margin: '3rem auto', padding: '0 1.5rem', animation: 'fade-in 0.6s ease-out' }}>
      <header className="page-header" style={{ display: 'block', textAlign: 'center', marginBottom: '3rem' }}>
        <h2 style={{ fontSize: '2.5rem', margin: '0 0 1rem 0' }}>更新日志</h2>
        <p className="page-header__description" style={{ margin: '0 auto', fontSize: '1.2rem' }}>
          追踪 ShieldChain 的每一次进化
        </p>
      </header>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        
        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto', position: 'relative' }}>
          <div style={{ position: 'absolute', left: '-1rem', top: '2rem', background: 'var(--color-accent)', color: 'white', padding: '0.25rem 0.75rem', borderRadius: '1rem', fontSize: '0.8rem', fontWeight: 'bold' }}>最新</div>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <Rocket className="nav-icon" size={20} color="var(--color-accent)" /> 
            v1.2.0 - 智能体 ReAct 升级
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-07-25</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>重构了前端的导航布局，加入了更加现代化的悬浮下拉菜单。</li>
            <li>新增了精美的系统主页和操作指引。</li>
            <li>升级了底层多智能体的状态机，在模拟模式下支持失败重试推理闭环。</li>
            <li>运营报告新增结构化调查推理链，按观测、定位、协同、定性、动作、验证和闭环回放公开证据依据。</li>
            <li>新增事件、终端检测、漏洞和身份认证四域证据覆盖，并明确标记未观测数据域。</li>
          </ul>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <GitCommit className="nav-icon" size={20} /> 
            v1.1.0 - RAG 知识库融合
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-06-15</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>引入本地离线 RAG 系统，支持上传安全知识库文档。</li>
            <li>智能体可以自动提取企业内网资产信息辅助研判。</li>
          </ul>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <FileCode className="nav-icon" size={20} /> 
            v1.0.0 - 核心系统上线
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-05-01</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>ShieldChain 核心框架正式发布，支持离线沙箱环境。</li>
            <li>实现钓鱼邮件攻击的自动化研判和人工干预。</li>
          </ul>
        </section>

      </div>
    </div>
  )
}
