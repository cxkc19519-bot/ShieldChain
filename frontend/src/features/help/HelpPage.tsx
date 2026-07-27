import React from 'react'
import { Shield, Brain, Workflow } from 'lucide-react'

export function HelpPage() {
  return (
    <div style={{ maxWidth: '800px', margin: '3rem auto', padding: '0 1.5rem', animation: 'fade-in 0.6s ease-out' }}>
      <header className="page-header" style={{ display: 'block', textAlign: 'center', marginBottom: '3rem' }}>
        <h2 style={{ fontSize: '2.5rem', margin: '0 0 1rem 0' }}>关于 ShieldChain</h2>
        <p className="page-header__description" style={{ margin: '0 auto', fontSize: '1.2rem' }}>
          下一代大模型驱动的自动安全运营中枢
        </p>
      </header>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        
        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <Shield className="nav-icon" size={20} /> 
            项目定位
          </h3>
          <p style={{ color: 'var(--color-text-muted)', lineHeight: '1.7', margin: 0 }}>
            盾链智御（ShieldChain）是一个面向网络安全运营（SecOps）的智能体（AI Agent）研究与演示项目。
            它的核心目标是将传统高度依赖人工的安全分析、事件调查和响应处置流程自动化，由大语言模型（LLM）扮演“超级安全分析师”的角色，自动闭环处理海量安全告警。
          </p>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <Workflow className="nav-icon" size={20} /> 
            核心能力
          </h3>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>
              <strong>多场景威胁模拟：</strong> 支持钓鱼攻击、勒索软件、挖矿木马、数据窃取等多种安全事件剧本的自动化模拟生成。
            </li>
            <li>
              <strong>智能证据收集与研判：</strong> 系统通过 RAG（检索增强生成）技术，赋予智能体查询企业内网资产、关联多源日志证据链的能力。
            </li>
            <li>
              <strong>ReAct 复杂推理闭环：</strong> 遇到阻力或异常（如防火墙封禁失败）时，智能体会利用 “观察-分类-重规划-验证” 的 ReAct 机制自动调整策略并调用网关执行备选方案。
            </li>
            <li>
              <strong>人工接管 API：</strong> 在触及敏感权限（安全边界）或大模型算力预算耗尽时，系统可无缝切换至人工审查和接管。
            </li>
          </ul>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <Brain className="nav-icon" size={20} /> 
            技术架构
          </h3>
          <p style={{ color: 'var(--color-text-muted)', lineHeight: '1.7', margin: 0 }}>
            本项目采用 Python (FastAPI) 作为核心调度后端，前端界面使用 React 构建。
            内置了多智能体编排引擎和可信工具调用网关，通过将复杂的安全编排抽象为工作流节点（Workflow），实现了 LLM 规划与确定性工程逻辑的有机结合。当前前端处于离线仿真模式展示，无需连网即可体验完整的防御闭环。
          </p>
        </section>

      </div>
    </div>
  )
}
