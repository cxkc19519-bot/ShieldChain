import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ReportsPage } from './ReportsPage'

const ID = '11111111-1111-4111-8111-111111111111'
const api = vi.hoisted(() => ({ deleteHistoricalReport: vi.fn(), listHistoricalReports: vi.fn(), loadReportBundle: vi.fn() }))
vi.mock('./api', () => api)
vi.mock('../tools/ToolsPage', () => ({ ToolsPage: ({ initialRunId }: { initialRunId: string }) => <div>处置操作：{initialRunId}</div> }))

const report = { run_id: ID, run_tracking_id: 'RUN-11111111', incident_id: ID, incident_tracking_id: 'INC-2026-0001', status: 'closed', threat_label: 'known-malicious-c2', endpoint: 'PC-023', created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T01:00:00Z', completed_at: '2026-07-24T01:00:00Z' }
const bundle = { audit: { events: [{ id: 'event-1', sequence: 1, event_type: 'run_created', occurred_at: '2026-07-24T00:01:00Z' }] }, investigation: { status: 'closed', assessment: { conclusion: 'confirmed_threat', risk_level: 'high', explanation: 'Evidence is incomplete, malformed, conflicting, or does not match all rules.' }, verification: { blocked: true } }, collaboration: null, react: null }

beforeEach(() => {
  api.deleteHistoricalReport.mockReset().mockResolvedValue(undefined)
  api.listHistoricalReports.mockReset().mockResolvedValue([report])
  api.loadReportBundle.mockReset().mockResolvedValue(bundle)
})

describe('ReportsPage', () => {
  it('lists historical reports and shows the native report detail workspace', async () => {
    render(<ReportsPage />)
    expect(await screen.findByText('INC-2026-0001')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByRole('heading', { name: '智能体协作' })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'ReAct 工作台' })).toBeVisible()
    expect(screen.getByText('调查运行已创建')).toBeVisible()
    expect(screen.getByText('已确认威胁')).toBeVisible()
    expect(screen.getByText('高风险')).toBeVisible()
    expect(screen.getByText('证据不完整、格式异常、相互矛盾，或未能满足全部研判规则。')).toBeVisible()
    expect(screen.queryByRole('heading', { name: '历史调查报告' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '返回历史报告' }))
    expect(await screen.findByRole('heading', { name: '历史调查报告' })).toBeVisible()
    expect(api.loadReportBundle).toHaveBeenCalledWith({ incidentId: ID, runId: ID }, expect.any(AbortSignal))
  })

  it('shows the trusted operation workspace for the selected report', async () => {
    render(<ReportsPage />)
    await screen.findByText('INC-2026-0001')
    fireEvent.click(screen.getAllByRole('button', { name: '操作' })[0])
    expect(await screen.findByText(`处置操作：${ID}`)).toBeVisible()
  })

  it('shows an empty state when no reports have been retained', async () => {
    api.listHistoricalReports.mockResolvedValue([])
    render(<ReportsPage />)
    expect(await screen.findByText('暂无历史报告')).toBeVisible()
    await waitFor(() => expect(api.listHistoricalReports).toHaveBeenCalled())
  })

  it('requires confirmation before deleting the local report record', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    render(<ReportsPage />)
    expect(await screen.findByText('INC-2026-0001')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '删除记录' }))
    expect(api.deleteHistoricalReport).not.toHaveBeenCalled()

    confirm.mockReturnValue(true)
    fireEvent.click(screen.getByRole('button', { name: '删除记录' }))
    await waitFor(() => expect(api.deleteHistoricalReport).toHaveBeenCalledWith(ID))
    expect(screen.queryByText('INC-2026-0001')).not.toBeInTheDocument()
    confirm.mockRestore()
  })})