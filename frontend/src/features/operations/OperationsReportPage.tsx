import { useCallback, useEffect, useState } from 'react'
import { FileDown, FileText, Play, ShieldCheck, Wrench } from 'lucide-react'
import { Link } from 'react-router-dom'

import { PageHeader } from '../../components/ui/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { createOperationsReport, listOperationsReports, type OperationsReport, type ToolCall } from './api'
import './operations.css'

function localInput(value: Date): string {
  const offset = value.getTimezoneOffset() * 60_000
  return new Date(value.getTime() - offset).toISOString().slice(0, 16)
}

function dateTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

function toolStatus(tool: ToolCall): string {
  if (tool.status === 'failed') return '调用失败 · 未取得可信结果'
  if (tool.status === 'empty') return '返回 0 项 · 无匹配记录'
  return `返回 ${tool.result_count} 项 · 调用完成`
}

const STEP_ICONS = [ShieldCheck, Wrench, FileText, ShieldCheck, FileText, Play]

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
        <header className="operations-detail__header"><div><p className="eyebrow">{selected.agent_name}</p><h2>{selected.id}</h2><p>{dateTime(selected.start_at)} 至 {dateTime(selected.end_at)}</p><p>{selected.run_status === 'legacy_without_run' ? '历史报告：无通用运行记录（legacy_without_run）' : `运行 ID：${selected.run_id}`}</p></div><div className="operations-downloads"><a href={`/api/v1/operations/reports/${encodeURIComponent(selected.id)}/download?format=markdown`}><FileDown size={16} />下载 Markdown</a><a href={`/api/v1/operations/reports/${encodeURIComponent(selected.id)}/download?format=html`}><FileDown size={16} />下载 HTML</a></div></header>
        <section aria-label="智能体执行阶段" className="operations-stages">
          {selected.stages.map((stage, index) => { const Icon = STEP_ICONS[index] ?? ShieldCheck; return <article key={stage.key}><Icon size={18} aria-hidden="true" /><div><strong>{index + 1}. {stage.label}</strong><p>{stage.detail}</p></div><span className={stage.status === 'fallback' ? 'is-fallback' : ''}>{stage.status === 'fallback' ? '保守降级' : '已完成'}</span></article> })}
        </section>
        <section className="operations-collaboration"><header><div><p className="eyebrow">多智能体协作</p><h3>角色协作轨迹</h3></div><span>公开摘要</span></header><div>{selected.collaboration.map((role) => <article key={role.role}><strong>第 {role.iteration} 轮 · {role.label}</strong><span className={role.status === 'fallback' ? 'is-fallback' : ''}>{role.status === 'fallback' ? '保守降级' : '已完成'}</span><p>{role.summary}</p><small>决策原因：{role.decision_reason}</small>{role.handoff_to && <small> · 交接至：{role.handoff_to}</small>}</article>)}</div></section>
        {selected.response_plan && <section className="operations-plan" aria-labelledby="operations-plan-title"><header><div><p className="eyebrow">严格结构化建议</p><h3 id="operations-plan-title">响应计划</h3></div><span>{selected.response_plan.generation_status === 'deterministic_fallback' ? '安全降级' : '编译通过'}</span></header><dl><dt>计划 ID</dt><dd><code>{selected.response_plan.plan_id}</code></dd><dt>生成时版本</dt><dd>第 {selected.response_plan.revision} 版</dd><dt>生成时状态</dt><dd>{selected.response_plan.status}</dd><dt>动作数</dt><dd>{selected.response_plan.action_count}</dd><dt>实时执行事实</dt><dd>请进入处置中心核验</dd></dl><p>{selected.response_plan.public_summary}</p>{selected.response_plan.fallback_reason_code && <code>{selected.response_plan.fallback_reason_code}</code>}<small>计划生成不代表接受、审批、执行或验证成功；报告保存的是生成时快照。</small>{selected.run_id && <div className="operations-plan__links"><Link to={`/response?run_id=${encodeURIComponent(selected.run_id)}`}>进入处置中心</Link><Link to={`/agents?run_id=${encodeURIComponent(selected.run_id)}`}>查看 ReAct 轨迹</Link></div>}</section>}
        <section className="operations-tools"><header><div><p className="eyebrow">受控数据获取</p><h3>ReAct 自主工具调用记录</h3></div><span>只读</span></header><div>{selected.tool_calls.length === 0 && <p>本次运行未选择运营数据工具。</p>}{selected.tool_calls.map((tool) => <article key={tool.name}><div><strong>{tool.label}</strong><span>{tool.name}</span></div><p>{tool.summary}</p><small>{toolStatus(tool)}</small>{tool.reason_code && <code>{tool.reason_code}</code>}{tool.items.length > 0 && <details><summary>查看规范化返回项</summary><ul>{tool.items.map((item) => <li key={item}>{item}</li>)}</ul></details>}</article>)}</div></section>
        <section className="operations-preview"><header><div><p className="eyebrow">格式转换与结果回显</p><h3>报告预览</h3></div><div><button type="button" className={preview === 'html' ? '' : 'secondary-button'} onClick={() => setPreview('html')}>HTML 预览</button><button type="button" className={preview === 'markdown' ? '' : 'secondary-button'} onClick={() => setPreview('markdown')}>Markdown</button></div></header>{preview === 'html' ? <iframe title={`${selected.id} HTML 报告预览`} sandbox="" srcDoc={selected.html} /> : <pre>{selected.markdown}</pre>}</section>
      </div>
    </div>}
  </section>
}
