import { useEffect, useState } from 'react'

import { EmptyState, ErrorState, LoadingState } from '../../components/ui/States'
import { getMcpPeers, getMcpStatus, getMcpTools } from '../mcp/api'
import type { McpPeer, McpStatus, McpTool } from '../mcp/types'
import './status.css'

type StatusData = { status: McpStatus | null; tools: McpTool[] | null; peers: McpPeer[] | null }

function message(value: unknown): string {
  return value instanceof Error ? value.message : '服务状态加载失败'
}

export function StatusPage() {
  const [data, setData] = useState<StatusData>({ status: null, tools: null, peers: null })
  const [errors, setErrors] = useState<string[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    void Promise.allSettled([
      getMcpStatus(controller.signal), getMcpTools(controller.signal), getMcpPeers(controller.signal),
    ]).then(([status, tools, peers]) => {
      if (controller.signal.aborted) return
      setData({
        status: status.status === 'fulfilled' ? status.value : null,
        tools: tools.status === 'fulfilled' ? tools.value : null,
        peers: peers.status === 'fulfilled' ? peers.value : null,
      })
      setErrors([
        ...(status.status === 'rejected' ? [`MCP Server：${message(status.reason)}`] : []),
        ...(tools.status === 'rejected' ? [`工具目录：${message(tools.reason)}`] : []),
        ...(peers.status === 'rejected' ? [`外部 peer：${message(peers.reason)}`] : []),
      ])
      setLoading(false)
    })
    return () => controller.abort()
  }, [])

  return <main className="status-page">
    <header><p className="eyebrow">公开只读投影</p><h2>服务与 MCP 状态</h2><p>显示服务端批准的状态、目录和 peer 摘要；不展示 endpoint、Token、Secret、原始错误或私有网络地址。</p></header>
    {loading && <LoadingState title="正在加载实时公开状态" />}
    {!loading && errors.length === 3 && <ErrorState title="公开状态暂不可用" detail={errors.join('；')} />}
    {errors.length > 0 && errors.length < 3 && <section className="status-warning" role="status"><strong>部分状态不可用</strong><ul>{errors.map((error) => <li key={error}>{error}</li>)}</ul></section>}
    {data.status && <section className="page-card status-summary"><header><div><p className="eyebrow">MCP Server</p><h3>{data.status.server_enabled ? '已启用' : '未启用'}</h3></div><span className={`status-badge ${data.status.server_enabled ? 'status-badge--success' : 'status-badge--warning'}`}>{data.status.boundary}</span></header><dl><div><dt>鉴权模式</dt><dd>{data.status.auth_mode}</dd></div><div><dt>服务版本</dt><dd>{data.status.server_version}</dd></div><div><dt>发布工具</dt><dd>{data.status.published_tool_count}</dd></div><div><dt>配置 peer</dt><dd>{data.status.configured_peer_count}</dd></div></dl><p>支持协议：{data.status.supported_protocol_versions.join('、')}</p></section>}
    {data.tools && <section className="page-card status-catalog"><header><div><p className="eyebrow">固定公开目录</p><h3>只读工具</h3></div><strong>{data.tools.length} 项</strong></header>{data.tools.length === 0 ? <EmptyState title="当前没有已发布工具" detail="Server 未启用或外部目录尚无可用批准快照。" /> : <div>{data.tools.map((tool) => <article key={`${tool.provider_id}:${tool.name}`}><header><strong>{tool.label}</strong><span>{tool.provider_kind === 'remote_mcp' ? '外部 MCP' : '内置'}</span></header><code>{tool.name}</code><p>{tool.description}</p><small>目录 {tool.catalog_revision} · Schema {tool.schema_revision}</small></article>)}</div>}</section>}
    {data.peers && <section className="page-card status-peers"><header><div><p className="eyebrow">脱敏连接摘要</p><h3>外部 MCP peers</h3></div><strong>{data.peers.length} 个</strong></header>{data.peers.length === 0 ? <p>未配置外部 MCP peer。</p> : <div>{data.peers.map((peer) => <article key={peer.peer_id}><header><strong>{peer.peer_id}</strong><span className="status-badge">{peer.health}</span></header><dl><div><dt>协议</dt><dd>{peer.protocol_version ?? '未发现'}</dd></div><div><dt>工具数</dt><dd>{peer.tool_count}</dd></div><div><dt>目录修订</dt><dd>{peer.catalog_revision ?? '无'}</dd></div><div><dt>原因码</dt><dd>{peer.reason_code ?? '无'}</dd></div></dl></article>)}</div>}</section>}
  </main>
}
