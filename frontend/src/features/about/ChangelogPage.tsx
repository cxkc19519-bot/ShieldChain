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
            v1.3.0 - 自动化安全运营闭环
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-09-07</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>打通流量回放、NTA 探针检测、Wazuh 告警接入与多智能体自动调查链路。</li>
            <li>新增随机演示回放能力，可自动触发告警分析、响应规划、可信工具调用和处置结果验证。</li>
            <li>安全运营报告升级为独立 HTML 归档，集中呈现跨域证据、攻击调查时间线、处置动作与执行回执。</li>
            <li>完善零人工演示闭环，在隔离环境中自动完成风险研判、策略授权、响应执行和状态复核。</li>
            <li>扩展网络流量、端点进程、资产上下文和威胁指标只读工具，增强多证据域自主调查能力。</li>
            <li>优化运营总览、实时告警、知识库和智能助手的交互与信息展示。</li>
          </ul>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto', position: 'relative' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <Rocket className="nav-icon" size={20} color="var(--color-accent)" /> 
            v1.2.0 - 多智能体协同与可信执行
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-08-18</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>建立总控、告警分诊、威胁调查、知识检索、响应规划和验证等专业智能体协作机制。</li>
            <li>引入受预算和停止条件约束的 ReAct 循环，支持观察、反馈和失败后的重新规划。</li>
            <li>接入可信工具网关，对策略授权、工具执行和结果验证进行统一审计。</li>
            <li>运营报告新增结构化攻击调查时间线，公开展示事实依据、智能体协作结论和闭环状态。</li>
            <li>完善网络流量、终端行为、身份账号、漏洞与日志等跨域证据关联能力。</li>
          </ul>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <GitCommit className="nav-icon" size={20} /> 
            v1.1.0 - 多源数据与知识增强
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-07-22</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>接入 Wazuh 告警、事件记录和资产安全数据，为智能体提供统一的调查上下文。</li>
            <li>引入本地知识库与语义检索能力，支持安全文档上传、分块、索引和版本管理。</li>
            <li>实现事件、告警、漏洞和弱口令四类只读工具，支撑智能体按任务自主获取证据。</li>
            <li>增加历史调查记录和审计信息，为后续分析提供可追溯依据。</li>
          </ul>
        </section>

        <section className="page-card" style={{ padding: '2rem', minHeight: 'auto' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--color-text)', fontSize: '1.25rem', marginTop: 0 }}>
            <FileCode className="nav-icon" size={20} /> 
            v1.0.0 - 项目基础版本
          </h3>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '1.5rem' }}>发布日期：2026-07-08</span>
          <ul style={{ listStyleType: 'disc', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--color-text-muted)', lineHeight: '1.6', margin: 0 }}>
            <li>完成 ShieldChain 安全运营平台的基础架构和前后端工作区。</li>
            <li>建立告警接入、调查任务、状态流转和安全运营报告的基础数据模型。</li>
            <li>实现本地部署、健康检查和容器化运行，为后续智能体能力迭代提供运行基础。</li>
          </ul>
        </section>

      </div>
    </div>
  )
}
