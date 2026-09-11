import React from 'react'

export function AboutPage() {
  return (
    <div style={{ maxWidth: '800px', margin: '3rem auto', padding: '0 1.5rem', animation: 'fade-in 0.6s ease-out' }}>
      <header className="page-header" style={{ display: 'block', textAlign: 'center', marginBottom: '3rem' }}>
        <h2 style={{ fontSize: '2.5rem', margin: '0 0 1rem 0' }}>关于我们</h2>
        <p className="page-header__description" style={{ margin: '0 auto', fontSize: '1.2rem' }}>
          电子科技大学计算机科学与工程学院（网络空间安全学院）
        </p>
      </header>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <p style={{ color: 'var(--color-text-muted)', lineHeight: '1.7', margin: 0 }}>
            我们是电子科技大学计算机科学与工程学院（网络空间安全学院）的一支学生创新团队，
            聚焦人工智能与网络空间安全的交叉研究与工程实践。团队主要关注大模型安全、
            Agent 安全、多智能体协同、可信工具调用，以及大模型在安全运营场景中的可靠应用。
            <br /><br />
            ShieldChain 是团队围绕智能化安全运营开展的一次实践探索。项目面向告警分析、
            跨域证据关联、风险研判、响应处置和结果验证等环节，研究如何让多个安全智能体在
            人工监督和安全约束下协同工作，形成可审计、可验证的安全运营闭环。
          </p>
        </section>
      </div>
    </div>
  )
}
