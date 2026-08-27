import { useCallback, useEffect, useState } from 'react'
import { BrainCircuit, CheckCircle2, FileDown, FileText, GitBranch, Play, RefreshCcw, ShieldCheck, Wrench } from 'lucide-react'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { createOperationsReport, listOperationsReports, type OperationsReport } from './api'
import './operations.css'

function localInput(value: Date): string {
  const offset = value.getTimezoneOffset() * 60_000
  return new Date(value.getTime() - offset).toISOString().slice(0, 16)
}

function dateTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

const STEP_ICONS = [ShieldCheck, Wrench, FileText, ShieldCheck, FileText, Play]

const TRACE_PHASE_LABELS: Record<string, string> = {
  observe: '观测', correlate: '定位', collaborate: '协同', decide: '定性与决策',
  act: '动作边界', verify: '验证', close: '闭环',
}

function traceStatus(value: string): string {
  return value === 'completed' ? '已完成' : value === 'blocked' ? '待人工处理' : '待执行'
}

function closureStatus(value: string): string {
  return { analysis_complete: '分析完成', awaiting_approval: '等待人工审批', verification_pending: '等待验证', closed: '已闭环' }[value] ?? value
}

export function OperationsReportPage() {
  const [startAt, setStartAt] = useState(() => localInput(new Date(Date.now() - 86_400_000)))
  const [endAt, setEndAt] = useState(() => localInput(new Date()))
  const [reports, setReports] = useState<OperationsReport[]>([])
  const [selected, setSelected] = useState<OperationsReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<'html' | 'markdown'>('html')

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    try {
      const next = await listOperationsReports(signal)
      if (!signal?.aborted) {
        setReports(next)
        setSelected((current) => current ? (next.find((item) => item.id === current.id) ?? current) : (next[0] ?? null))
      }
    } catch (reason) {
      if (!signal?.aborted) setError(reason instanceof Error ? reason.message : '加载运营报告失败')
    } finally { if (!signal?.aborted) setLoading(false) }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void refresh(controller.signal)
    return () => controller.abort()
  }, [refresh])

  const generate = async () => {
    if (!startAt || !endAt) { setError('请完整填写开始与结束时间。'); return }
    setGenerating(true)
    setError(null)
    try {
      const next = await createOperationsReport({ start_at: new Date(startAt).toISOString(), end_at: new Date(endAt).toISOString() })
      setReports((items) => [next, ...items.filter((item) => item.id !== next.id)])
      setSelected(next)
      setPreview('html')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '生成安全运营报告失败')
    } finally { setGenerating(false) }
  }

  return <section aria-labelledby="operations-title" className="page-card operations-page">
    <PageHeader
      id="operations-title"
      eyebrow="真实数据 · 多智能体安全运营"
      title="安全运营报告"
      description="安全运营报告智能体根据任务自主选择受授权的只读 MCP 工具，观察返回结果后继续分析、交接或结束；不会自动执行处置。"
    />

    <section className="operations-runner" aria-label="生成安全运营报告">
      <div className="operations-runner__inputs">
        <label>开始时间<input type="datetime-local" value={startAt} onChange={(event) => setStartAt(event.target.value)} disabled={generating} /></label>
        <label>结束时间<input type="datetime-local" value={endAt} onChange={(event) => setEndAt(event.target.value)} disabled={generating} /></label>
      </div>
      <button type="button" className="operations-runner__button" disabled={generating} onClick={() => void generate()}>
        <Play size={17} aria-hidden="true" />{generating ? '报告智能体分析中…' : '生成运营报告'}
      </button>
    </section>
    <p className="operations-boundary">受控边界：时间范围最多 31 天；MCP 工具只读；CVE 和弱口令结果均为线索，必须人工复核。</p>
    {error && <ErrorState title="报告操作未完成" detail={error} action={<button type="button" onClick={() => setError(null)}>关闭提示</button>} />}

    {loading && !selected && <LoadingState title="正在读取已生成的运营报告" />}
    {!loading && !selected && !error && <EmptyState title="尚无安全运营报告" detail="选择时间范围后，报告智能体会分析已接入的真实告警与离线 NTA 数据。" />}

    {selected && <div className="operations-workspace">
      <aside className="operations-history" aria-label="运营报告历史">
        <header><span>报告历史</span><button type="button" onClick={() => void refresh()} disabled={loading}>刷新</button></header>
        {reports.map((item) => <button key={item.id} type="button" className={item.id === selected.id ? 'is-selected' : ''} onClick={() => setSelected(item)}>
          <strong>{item.id}</strong><span>{dateTime(item.generated_at)}</span>
        </button>)}
      </aside>
      <div className="operations-detail">
        <header className="operations-detail__header"><div><p className="eyebrow">{selected.agent_name}</p><h2>{selected.id}</h2><p>{dateTime(selected.start_at)} 至 {dateTime(selected.end_at)}</p></div><div className="operations-downloads"><a href={`/api/v1/operations/reports/${encodeURIComponent(selected.id)}/download?format=markdown`}><FileDown size={16} />下载 Markdown</a><a href={`/api/v1/operations/reports/${encodeURIComponent(selected.id)}/download?format=html`}><FileDown size={16} />下载 HTML</a></div></header>
        <section aria-label="智能体执行阶段" className="operations-stages">
          {selected.stages.map((stage, index) => { const Icon = STEP_ICONS[index] ?? ShieldCheck; return <article key={stage.key}><Icon size={18} aria-hidden="true" /><div><strong>{index + 1}. {stage.label}</strong><p>{stage.detail}</p></div><span className={stage.status === 'fallback' ? 'is-fallback' : ''}>{stage.status === 'fallback' ? '保守降级' : '已完成'}</span></article> })}
        </section>
        <section className="operations-reasoning" aria-labelledby="reasoning-title">
          <header><div><p className="eyebrow">可审计推理过程</p><h3 id="reasoning-title">结构化调查推理链</h3></div><span><BrainCircuit size={15} aria-hidden="true" /> 不展示隐藏 CoT</span></header>
          <p className="operations-reasoning__hint">按“观测 → 定位 → 协同 → 定性 → 动作 → 验证 → 闭环”回放公开证据、角色交接和决策依据；未选择的数据域保持未知。</p>
          <ol className="operations-reasoning__timeline">
            {selected.reasoning_trace.map((step) => <li key={`${step.sequence}-${step.phase}`} className={`is-${step.status}`}>
              <div className="operations-reasoning__marker"><span>{step.sequence}</span></div>
              <div className="operations-reasoning__content"><div className="operations-reasoning__title"><strong>{step.title}</strong><span>{TRACE_PHASE_LABELS[step.phase] ?? step.phase} · {traceStatus(step.status)}</span></div><p>{step.detail}</p>{step.domains.length > 0 && <small>证据域：{step.domains.join('、')}</small>}{step.evidence.length > 0 && <details><summary>查看公开证据摘要（{step.evidence.length}）</summary><ul>{step.evidence.map((item, index) => <li key={`${step.sequence}-${index}`}>{item}</li>)}</ul></details>}</div>
            </li>)}
            {selected.reasoning_trace.length === 0 && <li className="operations-reasoning__empty">该历史报告未保存结构化推理链，请重新生成报告。</li>}
          </ol>
        </section>

        <section className="operations-collaboration" aria-labelledby="collaboration-title"><header><div><p className="eyebrow">跨域多智能体协同</p><h3 id="collaboration-title">角色交接与证据责任</h3></div><span><GitBranch size={15} aria-hidden="true" /> {selected.collaboration.length} 轮</span></header><div>{selected.collaboration.map((role) => <article key={`${role.role}-${role.iteration}`}><strong>第 {role.iteration} 轮 · {role.label}</strong><span className={role.status === 'fallback' ? 'is-fallback' : ''}>{role.status === 'fallback' ? '保守降级' : '已完成'}</span><p>{role.summary}</p>{role.evidence_domains.length > 0 && <small>负责域：{role.evidence_domains.join('、')}</small>}<small>决策依据：{role.decision_reason || '依据前序公开观察继续'}</small>{role.handoff_to && <small> → 交接给：{role.handoff_to}</small>}</article>)}</div></section>

        <section className="operations-cross-domain" aria-labelledby="cross-domain-title"><header><div><p className="eyebrow">统一证据面</p><h3 id="cross-domain-title">跨域证据覆盖</h3></div><span>不把缺失当成零</span></header><div>{selected.cross_domain.map((item) => <article key={item.key} className={item.status === 'not_observed' ? 'is-missing' : ''}><div><strong>{item.label}</strong><span>{item.source}</span></div><b>{item.status === 'observed' ? `${item.result_count} 项已观测` : '本轮未观测'}</b><p>{item.summary}</p></article>)}</div></section>

        <section className="operations-closure" aria-labelledby="closure-title"><header><div><p className="eyebrow">Observe · Decide · Act · Verify</p><h3 id="closure-title">安全运营闭环</h3></div><span className="operations-closure__status"><RefreshCcw size={14} aria-hidden="true" /> {closureStatus(selected.closure.status)}</span></header><div className="operations-closure__grid"><article><CheckCircle2 size={17} /><strong>观测</strong><p>{selected.closure.observed}</p></article><article><BrainCircuit size={17} /><strong>决策</strong><p>{selected.closure.decision}</p></article><article><ShieldCheck size={17} /><strong>动作</strong><p>{selected.closure.action}</p></article><article><RefreshCcw size={17} /><strong>验证与反馈</strong><p>{selected.closure.verification}</p><small>{selected.closure.feedback}</small></article></div><p className="operations-closure__boundary">{selected.closure.human_approval_required ? '高风险动作必须人工审批；验证失败时自动回到总控重新规划。' : '当前动作不需要人工审批。'}</p></section>
        <section className="operations-tools"><header><div><p className="eyebrow">受控数据获取</p><h3>ReAct 自主工具调用记录</h3></div><span>只读</span></header><div>{selected.tool_calls.length === 0 && <p>本次运行未选择运营数据工具。</p>}{selected.tool_calls.map((tool) => <article key={tool.name}><div><strong>{tool.label}</strong><span>{tool.name}</span></div><p>{tool.summary}</p><small>返回 {tool.result_count} 项 · {tool.status === 'empty' ? '无匹配记录' : '调用完成'}</small>{tool.items.length > 0 && <details><summary>查看规范化返回项</summary><ul>{tool.items.map((item) => <li key={item}>{item}</li>)}</ul></details>}</article>)}</div></section>
        <section className="operations-preview"><header><div><p className="eyebrow">格式转换与结果回显</p><h3>报告预览</h3></div><div><button type="button" className={preview === 'html' ? '' : 'secondary-button'} onClick={() => setPreview('html')}>HTML 预览</button><button type="button" className={preview === 'markdown' ? '' : 'secondary-button'} onClick={() => setPreview('markdown')}>Markdown</button></div></header>{preview === 'html' ? <iframe title={`${selected.id} HTML 报告预览`} sandbox="" srcDoc={selected.html} /> : <pre>{selected.markdown}</pre>}</section>
      </div>
    </div>}
  </section>
}
