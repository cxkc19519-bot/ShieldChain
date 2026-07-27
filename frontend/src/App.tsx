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
  const [attackResult, setAttackResult] = useState<{type: string, status: number | string, text: string} | null>(null)
  const [isAttacking, setIsAttacking] = useState(false)

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
        console.log("正在使用模拟数据展示。")
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  const handleAttack = async (type: string) => {
    setIsAttacking(true)
    setAttackResult(null)
    try {
      const response = await fetch('http://localhost:8000/api/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: type })
      })
      const result = await response.json()
      setAttackResult({
        type: result.type || type,
        status: result.status,
        text: result.message || result.text || 'Unknown Error'
      })
    } catch (error) {
      setAttackResult({ type, status: 'Network Error', text: String(error) })
    } finally {
      setIsAttacking(false)
    }
  }

  if (loading) return null

  return (
    <div className="dashboard-container">
      <header className="header">
        <h1 className="header-title">SAGA Provider 监控控制台</h1>
        <div className="status-badge">
          <div className="status-dot"></div>
          {data.status === 'online' ? '系统运行正常' : '系统离线'}
        </div>
      </header>

      <div className="metrics-grid">
        <div className="glass-panel metric-card">
          <span className="metric-label">已注册的智能体</span>
          <span className="metric-value">{data.metrics.total_agents}</span>
        </div>
        <div className="glass-panel metric-card">
          <span className="metric-label">已注册的用户</span>
          <span className="metric-value">{data.metrics.total_users}</span>
        </div>
        <div className="glass-panel metric-card">
          <span className="metric-label">活跃单次令牌 (SOTK)</span>
          <span className="metric-value">{data.metrics.active_tokens}</span>
        </div>
        <div className="glass-panel metric-card">
          <span className="metric-label">24小时内握手次数</span>
          <span className="metric-value">{data.metrics.handshakes_24h}</span>
        </div>
      </div>

      <section className="security-drill-section">
        <h2 className="section-title">安全攻击演练 (Security Drill)</h2>
        <div className="attack-buttons">
          <button 
            className="btn-attack btn-tamper" 
            onClick={() => handleAttack('tamper')}
            disabled={isAttacking}
          >
            模拟数据篡改攻击
          </button>
          <button 
            className="btn-attack btn-mitm" 
            onClick={() => handleAttack('mitm')}
            disabled={isAttacking}
          >
            模拟中间人窃取 (MITM)
          </button>
          <button 
            className="btn-attack btn-replay" 
            onClick={() => handleAttack('replay')}
            disabled={isAttacking}
          >
            模拟重放攻击
          </button>
        </div>
        
        {attackResult && (
          <div className="attack-result-panel glass-panel">
            <h3 className="result-title">🎯 攻击反馈: {attackResult.type}</h3>
            <div className="result-status">响应状态码: <span className="status-code">{attackResult.status}</span></div>
            <div className="result-text">被拦截详细信息: <span className="error-text">{attackResult.text}</span></div>
          </div>
        )}
      </section>

      <section className="agents-section">
        <h2 className="section-title">智能体名录</h2>
        <div className="agents-list">
          {data.agents.map((agent, i) => (
            <div key={i} className="glass-panel agent-row" style={{ animationDelay: `${0.5 + i * 0.1}s` }}>
              <div className="agent-info">
                <span className="agent-id">{agent.id}</span>
                <span className="agent-owner">拥有者: {agent.owner}</span>
              </div>
              <div className="agent-stats">
                <div className="stat-group">
                  <span className="stat-value">{agent.uptime}</span>
                  <span className="stat-label">在线时长</span>
                </div>
                <div className="stat-group">
                  <span className="stat-value" style={{ color: agent.status === 'online' ? 'var(--success-color)' : 'var(--error-color)' }}>
                    {agent.status === 'online' ? '在线' : '离线'}
                  </span>
                  <span className="stat-label">状态</span>
                </div>
              </div>
            </div>
          ))}
          {data.agents.length === 0 && (
            <div className="glass-panel">
              <p style={{ color: 'var(--text-secondary)' }}>暂无注册的智能体。</p>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}

export default App
