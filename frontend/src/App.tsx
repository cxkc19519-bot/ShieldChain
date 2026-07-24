import { useEffect, useState } from 'react'

interface Agent {
  id: string
  owner: string
  status: string
  uptime: string
}

interface Metrics {
  total_users: number
  total_agents: number
  active_tokens: number
  handshakes_24h: number
}

interface DashboardData {
  status: string
  metrics: Metrics
  agents: Agent[]
}

const MOCK_DATA: DashboardData = {
  status: 'online',
  metrics: {
    total_users: 12,
    total_agents: 45,
    active_tokens: 128,
    handshakes_24h: 342,
  },
  agents: [
    { id: 'urn:saga:agent:alice:agent-a', owner: 'alice', status: 'online', uptime: '99.9%' },
    { id: 'urn:saga:agent:bob:agent-b', owner: 'bob', status: 'online', uptime: '99.8%' },
    { id: 'urn:saga:agent:charlie:agent-c', owner: 'charlie', status: 'offline', uptime: '95.2%' },
  ]
}

function App() {
  const [data, setData] = useState<DashboardData>(MOCK_DATA)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Attempt to fetch from real API, fallback to mock if unreachable (e.g. CORS or server off)
    fetch('http://localhost:8000/metrics/dashboard')
      .then(res => res.json())
      .then(json => {
        if (json.metrics) {
          setData(json)
        }
      })
      .catch(() => {
        console.log("Using mock data for demonstration.")
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  if (loading) return null

  return (
    <div className="dashboard-container">
      <header className="header">
        <h1 className="header-title">SAGA Provider Dashboard</h1>
        <div className="status-badge">
          <div className="status-dot"></div>
          {data.status === 'online' ? 'System Operational' : 'System Offline'}
        </div>
      </header>

      <div className="metrics-grid">
        <div className="glass-panel metric-card">
          <span className="metric-label">Registered Agents</span>
          <span className="metric-value">{data.metrics.total_agents}</span>
        </div>
        <div className="glass-panel metric-card">
          <span className="metric-label">Registered Users</span>
          <span className="metric-value">{data.metrics.total_users}</span>
        </div>
        <div className="glass-panel metric-card">
          <span className="metric-label">Active SOTKs</span>
          <span className="metric-value">{data.metrics.active_tokens}</span>
        </div>
        <div className="glass-panel metric-card">
          <span className="metric-label">24H ACT Handshakes</span>
          <span className="metric-value">{data.metrics.handshakes_24h}</span>
        </div>
      </div>

      <section className="agents-section">
        <h2 className="section-title">Agents Directory</h2>
        <div className="agents-list">
          {data.agents.map((agent, i) => (
            <div key={i} className="glass-panel agent-row" style={{ animationDelay: `${0.5 + i * 0.1}s` }}>
              <div className="agent-info">
                <span className="agent-id">{agent.id}</span>
                <span className="agent-owner">Owner: {agent.owner}</span>
              </div>
              <div className="agent-stats">
                <div className="stat-group">
                  <span className="stat-value">{agent.uptime}</span>
                  <span className="stat-label">Uptime</span>
                </div>
                <div className="stat-group">
                  <span className="stat-value" style={{ color: agent.status === 'online' ? 'var(--success-color)' : 'var(--error-color)' }}>
                    {agent.status.toUpperCase()}
                  </span>
                  <span className="stat-label">Status</span>
                </div>
              </div>
            </div>
          ))}
          {data.agents.length === 0 && (
            <div className="glass-panel">
              <p style={{ color: 'var(--text-secondary)' }}>No agents registered yet.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}

export default App
