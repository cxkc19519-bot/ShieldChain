import React from 'react'

export function AboutPage() {
  return (
    <div style={{ maxWidth: '800px', margin: '3rem auto', padding: '0 1.5rem', animation: 'fade-in 0.6s ease-out' }}>
      <header className="page-header" style={{ display: 'block', textAlign: 'center', marginBottom: '3rem' }}>
        <h2 style={{ fontSize: '2.5rem', margin: '0 0 1rem 0' }}>关于我们</h2>
        <p className="page-header__description" style={{ margin: '0 auto', fontSize: '1.2rem' }}>
          盾链智御开发团队
        </p>
      </header>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <p style={{ color: 'var(--color-text-muted)', lineHeight: '1.7', margin: 0 }}>
            我们是一支专注于人工智能与网络安全交叉领域的探索团队。
            随着大语言模型（LLM）的爆发，我们相信未来的安全运营中心（SOC）将不再是劳动密集型的“告警分析厂”，
            而是一个由 AI 智能体高度自治、人类安全专家仅负责审批和高阶对抗的“智能中枢”。
            <br /><br />
            ShieldChain 便是这一理念的雏形，致力于将枯燥的日志研判、繁琐的证据收集和复杂的溯源排查交给机器，让人类回归到真正的安全战略思考中。
          </p>
        </section>
      </div>
    </div>
  )
}
