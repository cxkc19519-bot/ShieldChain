import React from 'react'
import { Link } from 'react-router-dom'
import {
  BookOpenCheck, Bug, FileCheck2, Radar, Route, SearchCheck, ShieldCheck,
  Sparkles, Workflow,
} from 'lucide-react'
import './help.css'

const agents = [
  { name: '总控智能体', tag: 'ORCHESTRATOR', icon: Workflow, description: '理解运营目标，拆解调查任务，协调专业智能体，并依据每轮观测结果决定继续调查、处置、重规划或结束。' },
  { name: '告警分诊智能体', tag: 'TRIAGE', icon: Radar, description: '接收 Wazuh 等来源的告警，完成去重、优先级判断与初步分类，把真正需要调查的事件送入闭环。' },
  { name: '威胁研判智能体', tag: 'INVESTIGATION', icon: SearchCheck, description: '关联流量、端点、身份与日志证据，还原攻击路径，形成可展示、可核验的调查结论与证据时间线。' },
  { name: '知识检索智能体', tag: 'KNOWLEDGE', icon: BookOpenCheck, description: '从已发布的本地知识库中检索与当前事件相关的规则、漏洞和处置依据，为研判提供引用证据。' },
  { name: '响应规划智能体', tag: 'RESPONSE', icon: Route, description: '根据风险、资产和策略授权生成处置计划，选择防火墙封禁、端点隔离等受控工具及其参数。' },
  { name: '验证智能体', tag: 'VERIFICATION', icon: ShieldCheck, description: '检查工具回执和威胁状态；若处置未生效，则把失败原因反馈给总控智能体，触发重新规划。' },
  { name: '报告智能体', tag: 'REPORTING', icon: FileCheck2, description: '汇总调查、授权、执行、验证和重规划轨迹，生成可独立查看、下载和审计的安全运营报告。' },
  { name: '漏洞研判智能体', tag: 'VULNERABILITY', icon: Bug, description: '关联扫描发现、资产风险与知识库建议，跟踪漏洞从发现、修复到复测关闭的完整生命周期。' },
]

const pages = [
  ['运营总览', '查看告警、闭环处置、智能体运行和证据覆盖的总体态势。'],
  ['实时告警', '观察随机流量回放触发的告警，以及智能体自动调查后的结论。'],
  ['安全运营报告', '按次查看完整调查报告、工具调用回执、验证结果与审计证据。'],
  ['漏洞闭环', '展示漏洞发现、研判、修复建议、复测与关闭状态。'],
  ['知识库', '管理供智能体检索引用的本地安全知识和文档版本。'],
  ['智能助手', '用自然语言查询当前安全态势、证据和历史运营结果。'],
]

export function HelpPage() {
  return (
    <article className="help-guide">
      <header className="help-guide__hero">
        <div className="help-guide__eyebrow"><Sparkles size={16} /> 项目说明</div>
        <h1>ShieldChain 使用说明</h1>
        <p>ShieldChain 是一个面向安全运营的多智能体演示平台。它以随机流量回放产生的真实告警为入口，自动完成跨域调查、响应规划、模拟工具处置、效果验证和报告归档，集中展示智能体如何应对安全异常。</p>
        <div className="help-guide__actions">
          <Link className="button" to="/dashboard">进入运营总览</Link>
          <Link className="button button-secondary" to="/operations-report">查看运营报告</Link>
        </div>
      </header>

      <section className="help-guide__section" aria-labelledby="help-core-title">
        <div className="help-guide__section-heading"><span>01</span><div><h2 id="help-core-title">项目核心</h2><p>从威胁发现到可信验证的零人工闭环。</p></div></div>
        <div className="help-flow" aria-label="自动安全运营流程">
          {['发现', '调查', '规划', '执行', '验证', '报告'].map((step, index) => (
            <React.Fragment key={step}>
              <div className="help-flow__step"><strong>{String(index + 1).padStart(2, '0')}</strong><span>{step}</span></div>
              {index < 5 && <span className="help-flow__arrow" aria-hidden="true">→</span>}
            </React.Fragment>
          ))}
        </div>
        <p className="help-guide__note">页面展示的是智能体可公开审计的证据、决策摘要和工具轨迹，不暴露模型的隐藏推理过程；可信工具网关属于执行基础设施，不单独算作智能体。</p>
      </section>

      <section className="help-guide__section" aria-labelledby="help-agents-title">
        <div className="help-guide__section-heading"><span>02</span><div><h2 id="help-agents-title">智能体团队</h2><p>一个总控智能体协调七个专业智能体。</p></div></div>
        <div className="help-agent-grid">
          {agents.map(({ name, tag, icon: Icon, description }) => (
            <article className="help-agent" key={name}>
              <div className="help-agent__icon"><Icon size={22} /></div>
              <div className="help-agent__content"><span>{tag}</span><h3>{name}</h3><p>{description}</p></div>
            </article>
          ))}
        </div>
      </section>

      <section className="help-guide__section" aria-labelledby="help-pages-title">
        <div className="help-guide__section-heading"><span>03</span><div><h2 id="help-pages-title">页面导航</h2><p>每个页面只承担一个清晰的演示职责。</p></div></div>
        <div className="help-page-list">
          {pages.map(([name, description], index) => (
            <div className="help-page-list__item" key={name}><strong>{String(index + 1).padStart(2, '0')}</strong><h3>{name}</h3><p>{description}</p></div>
          ))}
        </div>
      </section>

    </article>
  )
}
