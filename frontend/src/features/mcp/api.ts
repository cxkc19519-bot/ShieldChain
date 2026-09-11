import type { McpPeer, McpRunCall, McpStatus, McpTool } from './types'

const API_ROOT = '/api/v1/mcp'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid object')
  return value as Record<string, unknown>
}
function text(value: unknown): string { if (typeof value !== 'string') throw new Error('invalid text'); return value }
function bool(value: unknown): boolean { if (typeof value !== 'boolean') throw new Error('invalid boolean'); return value }
function number(value: unknown): number { if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error('invalid number'); return value }
function nullableText(value: unknown): string | null { return value === null ? null : text(value) }
function strings(value: unknown): string[] { if (!Array.isArray(value)) throw new Error('invalid list'); return value.map(text) }
function literal<T extends string>(value: unknown, allowed: readonly T[]): T { const item = text(value); if (!allowed.includes(item as T)) throw new Error('invalid enum'); return item as T }

async function request(path: string, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(`${API_ROOT}${path}`, { signal })
  let body: unknown
  try { body = await response.json() } catch { throw new Error('MCP 状态服务返回了无效响应') }
  if (!response.ok) {
    try { throw new Error(text(record(record(body).error).message)) } catch (error) {
      if (error instanceof Error && !error.message.startsWith('invalid')) throw error
      throw new Error(`MCP 状态请求失败（${response.status}）`)
    }
  }
  return body
}

function parseStatus(value: unknown): McpStatus {
  const item = record(value)
  return {
    server_enabled: bool(item.server_enabled),
    auth_mode: literal(item.auth_mode, ['disabled', 'oauth']),
    supported_protocol_versions: strings(item.supported_protocol_versions),
    server_version: text(item.server_version),
    published_tool_count: number(item.published_tool_count),
    configured_peer_count: number(item.configured_peer_count),
    boundary: literal(item.boundary, ['read_only']),
  }
}

function parseTool(value: unknown): McpTool {
  const item = record(value)
  return {
    name: text(item.name), label: text(item.label), description: text(item.description),
    provider_kind: literal(item.provider_kind, ['builtin', 'remote_mcp']),
    provider_id: text(item.provider_id), classification: literal(item.classification, ['read_only']),
    allowed_roles: strings(item.allowed_roles), catalog_revision: text(item.catalog_revision),
    schema_revision: text(item.schema_revision),
  }
}

function parsePeer(value: unknown): McpPeer {
  const item = record(value)
  return {
    peer_id: text(item.peer_id), enabled: bool(item.enabled),
    network_policy: literal(item.network_policy, ['public_https', 'internal_https']),
    health: literal(item.health, ['disabled', 'undiscovered', 'healthy', 'expired', 'rejected']),
    protocol_version: nullableText(item.protocol_version), catalog_revision: nullableText(item.catalog_revision),
    tool_count: number(item.tool_count), reason_code: nullableText(item.reason_code),
    discovered_at: nullableText(item.discovered_at), expires_at: nullableText(item.expires_at),
  }
}

function parseRunCall(value: unknown): McpRunCall {
  const item = record(value)
  return {
    id: text(item.id), role: nullableText(item.role),
    direction: literal(item.direction, ['internal', 'mcp_inbound', 'mcp_outbound']),
    provider_kind: literal(item.provider_kind, ['builtin', 'rag', 'remote_mcp']),
    provider_id: text(item.provider_id), tool_alias: text(item.tool_alias),
    catalog_revision: text(item.catalog_revision), schema_revision: text(item.schema_revision),
    status: literal(item.status, ['running', 'succeeded', 'empty', 'failed', 'timed_out', 'cancelled', 'rejected', 'unknown']),
    reason_code: nullableText(item.reason_code), result_count: number(item.result_count),
    summary: nullableText(item.summary), duration_ms: item.duration_ms === null ? null : number(item.duration_ms),
    attempt: number(item.attempt), truncated: bool(item.truncated), created_at: text(item.created_at),
    finished_at: nullableText(item.finished_at),
  }
}

function list<T>(value: unknown, parser: (item: unknown) => T): T[] {
  const items = record(value).items
  if (!Array.isArray(items)) throw new Error('invalid list')
  return items.map(parser)
}

export async function getMcpStatus(signal?: AbortSignal): Promise<McpStatus> {
  try { return parseStatus(await request('/status', signal)) } catch (error) {
    if (error instanceof Error && !error.message.startsWith('invalid')) throw error
    throw new Error('MCP 状态数据不符合公开契约')
  }
}

export async function getMcpTools(signal?: AbortSignal): Promise<McpTool[]> {
  try { return list(await request('/tools', signal), parseTool) } catch (error) {
    if (error instanceof Error && !error.message.startsWith('invalid')) throw error
    throw new Error('MCP 工具目录不符合公开契约')
  }
}

export async function getMcpPeers(signal?: AbortSignal): Promise<McpPeer[]> {
  try { return list(await request('/peers', signal), parsePeer) } catch (error) {
    if (error instanceof Error && !error.message.startsWith('invalid')) throw error
    throw new Error('MCP peer 状态不符合公开契约')
  }
}

export async function getMcpRunCalls(runId: string, signal?: AbortSignal): Promise<McpRunCall[]> {
  if (!UUID.test(runId)) throw new Error('请输入有效的调查运行 ID')
  try { return list(await request(`/runs/${encodeURIComponent(runId)}/calls`, signal), parseRunCall) } catch (error) {
    if (error instanceof Error && !error.message.startsWith('invalid')) throw error
    throw new Error('MCP 调用记录不符合公开契约')
  }
}
