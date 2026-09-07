export interface McpStatus {
  server_enabled: boolean
  auth_mode: 'disabled' | 'oauth'
  supported_protocol_versions: string[]
  server_version: string
  published_tool_count: number
  configured_peer_count: number
  boundary: 'read_only'
}

export interface McpTool {
  name: string
  label: string
  description: string
  provider_kind: 'builtin' | 'remote_mcp'
  provider_id: string
  classification: 'read_only'
  allowed_roles: string[]
  catalog_revision: string
  schema_revision: string
}

export interface McpPeer {
  peer_id: string
  enabled: boolean
  network_policy: 'public_https' | 'internal_https'
  health: 'disabled' | 'undiscovered' | 'healthy' | 'expired' | 'rejected'
  protocol_version: string | null
  catalog_revision: string | null
  tool_count: number
  reason_code: string | null
  discovered_at: string | null
  expires_at: string | null
}

export interface McpRunCall {
  id: string
  role: string | null
  direction: 'internal' | 'mcp_inbound' | 'mcp_outbound'
  provider_kind: 'builtin' | 'rag' | 'remote_mcp'
  provider_id: string
  tool_alias: string
  catalog_revision: string
  schema_revision: string
  status: 'running' | 'succeeded' | 'empty' | 'failed' | 'timed_out' | 'cancelled' | 'rejected' | 'unknown'
  reason_code: string | null
  result_count: number
  summary: string | null
  duration_ms: number | null
  attempt: number
  truncated: boolean
  created_at: string
  finished_at: string | null
}
