import type { CollaborationTrajectory } from '../agents/types'
import type { McpRunCall } from '../mcp/types'
import type { OperationsReport } from '../operations/api'
import type { ResponsePlan } from './types'

const ROLE_LABELS: Record<string, string> = {
  superagent: '总控智能体',
  alert_triage: '告警分诊',
  threat_investigation: '威胁研判',
  knowledge_retrieval: '知识检索',
  response_planning: '响应规划',
  verification: '处置验证',
  reporting: '报告生成',
}
const PHASE_LABELS: Record<string, string> = {
  observe: '流量与告警观测',
  correlate: '跨域证据关联',
  collaborate: '智能体协同研判',
  decide: '攻击定性与决策',
  act: '受控响应建议',
  verify: '处置效果验证',
  close: '调查闭环归档',
}

type TimelineItem = {
  id: string
  occurredAt: string
  stage: string
  title: string
  detail: string
  meta: string
  evidence: string[]
  warning?: string
}

function roleLabel(value: string): string { return ROLE_LABELS[value] ?? value }
function dateTime(value: string): string {
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false })
}

export function InvestigationTimeline({
  trajectory,
  report,
  mcpCalls,
  plan,
}: {
  trajectory: CollaborationTrajectory | null
  report: OperationsReport | null
  mcpCalls: McpRunCall[] | null
  plan: ResponsePlan | null
}) {
  const handoffs: TimelineItem[] = (trajectory?.handoffs ?? []).map((item) => ({
    id: `handoff-${item.id}`,
    occurredAt: item.created_at,
    stage: roleLabel(item.receiver),
    title: `${roleLabel(item.sender)} → ${roleLabel(item.receiver)}`,
    detail: item.conclusion,
    meta: `置信度 ${Math.round(item.confidence * 100)}%`,
    evidence: item.citations.map((citation) => citation.source_id),
    warning: item.open_questions.length ? `待补证：${item.open_questions.join('、')}` : undefined,
  }))
  const reportSteps: TimelineItem[] = (report?.reasoning_trace ?? []).map((item) => ({
    id: `report-step-${item.sequence}`,
    occurredAt: report?.generated_at ?? '',
    stage: PHASE_LABELS[item.phase] ?? item.phase,
    title: item.title,
    detail: item.detail,
    meta: `${item.status} · 置信度 ${Math.round(item.confidence * 100)}%${item.domains.length ? ` · ${item.domains.join('、')}` : ''}`,
    evidence: item.evidence,
    warning: item.status !== 'completed' ? '该阶段仍需人工补证或批准。' : undefined,
  }))
  const observations: TimelineItem[] = (mcpCalls ?? []).map((item) => ({
    id: `mcp-${item.id}`,
    occurredAt: item.created_at,
    stage: '证据关联',
    title: `${roleLabel(item.role ?? 'superagent')}调用 ${item.tool_alias}`,
    detail: item.summary ?? '工具调用未形成公开摘要。',
    meta: `${item.status} · ${item.result_count} 项结果${item.duration_ms === null ? '' : ` · ${item.duration_ms} ms`}`,
    evidence: [`调用 ${item.id}`, `目录 ${item.catalog_revision}`, `Schema ${item.schema_revision}`],
    warning: item.reason_code ? `原因码：${item.reason_code}` : undefined,
  }))
  const items = [...reportSteps, ...handoffs, ...observations].sort((left, right) => (
    new Date(left.occurredAt).getTime() - new Date(right.occurredAt).getTime()
  ))
  const currentPlan = plan?.revisions.find((item) => item.revision === plan.current_revision)

  return <section className="investigation-timeline" aria-labelledby="investigation-timeline-title">
    <header>
      <div><p className="eyebrow">公开证据 · 可审计研判链</p><h3 id="investigation-timeline-title">智能体攻击调查时间线</h3></div>
      <span>{items.length + (currentPlan ? 1 : 0)} 个阶段</span>
    </header>
    <p className="investigation-timeline__summary">{trajectory?.shared_summary ?? report?.closure.observed ?? '调查结果已保存，等待人工复核。'}</p>
    {(trajectory?.confirmed_facts.length ?? 0) > 0 && <div className="investigation-timeline__facts" aria-label="已确认事实">
      {trajectory?.confirmed_facts.map((fact, index) => <span key={`${fact}-${index}`}>{fact}</span>)}
    </div>}
    {items.length === 0 && !currentPlan ? <p className="investigation-timeline__empty">本次运行尚未形成可展示的角色交接、工具观察或响应计划。</p> : <ol>
      {items.map((item, index) => <li key={item.id}>
        <span className="investigation-timeline__index">{index + 1}</span>
        <article>
          <header><div><span>{item.stage}</span><strong>{item.title}</strong></div><time dateTime={item.occurredAt}>{dateTime(item.occurredAt)}</time></header>
          <p>{item.detail}</p>
          <small>{item.meta}</small>
          {item.evidence.length > 0 && <div className="investigation-timeline__evidence" aria-label={`${item.title} 证据引用`}>
            {item.evidence.map((evidence) => <code key={evidence}>{evidence}</code>)}
          </div>}
          {item.warning && <p className="investigation-timeline__warning">{item.warning}</p>}
        </article>
      </li>)}
      {currentPlan && <li>
        <span className="investigation-timeline__index">{items.length + 1}</span>
        <article className="investigation-timeline__plan">
          <header><div><span>响应规划</span><strong>形成处置建议</strong></div><time dateTime={plan?.updated_at}>{dateTime(plan?.updated_at ?? '')}</time></header>
          <p>{currentPlan.public_summary}</p>
          <small>{currentPlan.actions.length} 项建议 · 当前状态 {plan?.status}</small>
          <div className="investigation-timeline__evidence">
            {currentPlan.actions.flatMap((action) => action.evidence_ids).filter((value, index, all) => all.indexOf(value) === index).map((evidence) => <code key={evidence}>{evidence}</code>)}
          </div>
        </article>
      </li>}
    </ol>}
    <p className="investigation-timeline__boundary">此时间线仅展示服务端保存的公开结论、工具回执和证据引用；不展示隐藏思维链、原始提示词或凭据。</p>
  </section>
}
