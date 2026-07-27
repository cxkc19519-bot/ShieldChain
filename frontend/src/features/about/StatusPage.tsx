import React from 'react'
import { Activity, CheckCircle, Clock } from 'lucide-react'

export function StatusPage() {
  return (
    <div style={{ maxWidth: '800px', margin: '3rem auto', padding: '0 1.5rem', animation: 'fade-in 0.6s ease-out' }}>
      <header className="page-header" style={{ display: 'block', textAlign: 'center', marginBottom: '3rem' }}>
        <h2 style={{ fontSize: '2.5rem', margin: '0 0 1rem 0' }}>服务状态</h2>
        <p className="page-header__description" style={{ margin: '0 auto', fontSize: '1.2rem' }}>
          各个系统模块的实时运行监控
        </p>
      </header>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '2rem', padding: '1rem', background: 'var(--color-status-healthy-bg)', borderRadius: '0.8rem', border: '1px solid var(--color-status-healthy)' }}>
            <CheckCircle color="var(--color-status-healthy)" size={24} />
            <span style={{ color: 'var(--color-status-healthy)', fontWeight: 700, fontSize: '1.1rem' }}>所有系统运行正常</span>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {[
              { name: 'API 网关', status: '正常运行', uptime: '99.99%' },
              { name: '多智能体编排引擎', status: '正常运行', uptime: '99.98%' },
              { name: '知识库检索 (RAG)', status: '正常运行', uptime: '100%' },
              { name: '沙箱仿真环境', status: '正常运行', uptime: '99.95%' },
            ].map((service, idx) => (
              <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', borderBottom: '1px solid var(--color-border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Activity size={18} color="var(--color-text-muted)" />
                  <span style={{ fontWeight: 600, color: 'var(--color-text)' }}>{service.name}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
                  <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>
                    <Clock size={14} style={{ verticalAlign: 'text-bottom', marginRight: '0.25rem' }} />
                    在线率: {service.uptime}
                  </span>
                  <span className="status-badge status-badge--success">{service.status}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}
