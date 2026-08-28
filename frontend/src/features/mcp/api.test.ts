import { afterEach, describe, expect, it, vi } from 'vitest'

import { getMcpPeers, getMcpRunCalls, getMcpStatus, getMcpTools } from './api'

const ID = '11111111-1111-4111-8111-111111111111'
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('MCP public API', () => {
  it('validates status, catalog, peer, and run-call projections', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ server_enabled: true, auth_mode: 'oauth', supported_protocol_versions: ['2026-07-28'], server_version: '0.1.0', published_tool_count: 4, configured_peer_count: 1, boundary: 'read_only', endpoint: 'private' }))
      .mockResolvedValueOnce(response({ items: [{ name: 'security.alerts.list', label: '告警', description: '只读告警摘要', provider_kind: 'builtin', provider_id: 'shieldchain.operations', classification: 'read_only', allowed_roles: ['mcp_client'], catalog_revision: 'builtin-v1', schema_revision: 'schema-v1', token: 'secret' }] }))
      .mockResolvedValueOnce(response({ items: [{ peer_id: 'approved-peer', enabled: true, network_policy: 'public_https', health: 'healthy', protocol_version: '2026-07-28', catalog_revision: 'catalog-v1', tool_count: 1, reason_code: null, discovered_at: '2026-08-24T00:00:00Z', expires_at: '2026-08-24T01:00:00Z', endpoint: 'private' }] }))
      .mockResolvedValueOnce(response({ items: [{ id: ID, role: 'reporting', direction: 'mcp_outbound', provider_kind: 'remote_mcp', provider_id: 'approved-peer', tool_alias: 'external.approved.alerts_list', catalog_revision: 'catalog-v1', schema_revision: 'schema-v1', status: 'succeeded', reason_code: null, result_count: 2, summary: '返回两个公开摘要。', duration_ms: 10, attempt: 1, truncated: false, created_at: '2026-08-24T00:00:00Z', finished_at: '2026-08-24T00:00:01Z', raw_payload: 'private' }] }))
    vi.stubGlobal('fetch', fetchMock)

    expect((await getMcpStatus()).server_enabled).toBe(true)
    expect(await getMcpTools()).toHaveLength(1)
    expect((await getMcpPeers())[0].health).toBe('healthy')
    const calls = await getMcpRunCalls(ID)
    expect(calls[0].catalog_revision).toBe('catalog-v1')
    expect(calls[0]).not.toHaveProperty('raw_payload')
  })

  it('rejects malformed enums instead of trusting TypeScript assertions', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ server_enabled: true, auth_mode: 'none', supported_protocol_versions: [], server_version: '0.1.0', published_tool_count: 0, configured_peer_count: 0, boundary: 'read_only' })))
    await expect(getMcpStatus()).rejects.toThrow('不符合公开契约')
  })
})
