import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { StatusPage } from './StatusPage'

const api = vi.hoisted(() => ({ getMcpStatus: vi.fn(), getMcpTools: vi.fn(), getMcpPeers: vi.fn() }))
vi.mock('../mcp/api', () => api)

beforeEach(() => Object.values(api).forEach((mock) => mock.mockReset()))

describe('StatusPage', () => {
  it('renders partial, redacted MCP status without claiming all systems are healthy', async () => {
    api.getMcpStatus.mockResolvedValue({ server_enabled: true, auth_mode: 'oauth', supported_protocol_versions: ['2026-07-28'], server_version: '0.1.0', published_tool_count: 1, configured_peer_count: 1, boundary: 'read_only' })
    api.getMcpTools.mockResolvedValue([{ name: 'external.approved.alerts_list', label: '批准告警', description: '只读摘要', provider_kind: 'remote_mcp', provider_id: 'approved-peer', classification: 'read_only', allowed_roles: ['reporting'], catalog_revision: 'catalog-v1', schema_revision: 'schema-v1', endpoint: 'https://private/mcp', token: 'secret' }])
    api.getMcpPeers.mockRejectedValue(new Error('peer status unavailable'))
    render(<StatusPage />)

    expect(await screen.findByText('部分状态不可用')).toBeVisible()
    expect(screen.getByText('批准告警')).toBeVisible()
    expect(screen.queryByText(/https:\/\/private|secret/)).not.toBeInTheDocument()
    expect(screen.queryByText('所有系统运行正常')).not.toBeInTheDocument()
  })

  it('aborts all page-owned requests on unmount', async () => {
    const signals: AbortSignal[] = []
    for (const method of Object.values(api)) method.mockImplementation((signal: AbortSignal) => { signals.push(signal); return new Promise(() => undefined) })
    const view = render(<StatusPage />)
    await waitFor(() => expect(signals).toHaveLength(3))
    view.unmount()
    expect(signals.every((signal) => signal.aborted)).toBe(true)
  })
})
