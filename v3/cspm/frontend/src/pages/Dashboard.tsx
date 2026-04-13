import React, { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts'
import { ShieldAlert, Database, BookOpen, TrendingUp, Cloud, AlertTriangle } from 'lucide-react'
import api from '../utils/api'

const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', informational: '#60a5fa' }
const PROV_COLORS: Record<string, string> = { aws: '#f97316', azure: '#60a5fa', gcp: '#34d399', ibm: '#a78bfa', oci: '#fb7185' }

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.stats().then(s => { setStats(s); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  if (loading) return <LoadingState />
  if (!stats) return <div style={{ padding: 32, color: 'var(--text-2)' }}>Failed to load dashboard. Is the backend running?</div>

  const sevData = ['critical', 'high', 'medium', 'low', 'informational'].map(s => ({
    name: s, value: (stats as any)[s] || 0, color: SEV_COLORS[s as keyof typeof SEV_COLORS]
  })).filter(d => d.value > 0)

  const provData = Object.entries(stats.providers || {}).map(([k, v]) => ({
    name: k.toUpperCase(), value: v as number, color: PROV_COLORS[k] || '#64748b'
  }))

  const famData = Object.entries(stats.families || {})
    .sort((a, b) => (b[1] as number) - (a[1] as number))
    .slice(0, 8)
    .map(([k, v]) => ({ name: k, value: v as number }))

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 4 }}>Security Posture Dashboard</h1>
        <p style={{ color: 'var(--text-2)', fontSize: 13 }}>Real-time posture across AWS, Azure, GCP, IBM Cloud, and OCI</p>
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14, marginBottom: 24 }}>
        <StatCard label="Open Findings" value={stats.open_findings} color="var(--crit)" icon={<ShieldAlert size={18} />} />
        <StatCard label="Critical" value={stats.critical} color="#ef4444" />
        <StatCard label="High" value={stats.high} color="#f97316" />
        <StatCard label="Medium" value={stats.medium} color="#eab308" />
        <StatCard label="Low" value={stats.low} color="#22c55e" />
        <StatCard label="Total Assets" value={stats.total_assets} color="var(--blue-l)" icon={<Database size={18} />} />
        <StatCard label="Checks Loaded" value={stats.total_checks} color="var(--cyan)" icon={<BookOpen size={18} />} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* 7-day trend */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <TrendingUp size={16} color="var(--blue-l)" />
            <span style={{ fontWeight: 600, fontSize: 13 }}>New Findings — Last 7 Days</span>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={stats.trend_7d || []}>
              <XAxis dataKey="date" tick={{ fill: 'var(--text-2)', fontSize: 10 }} tickFormatter={d => d.slice(5)} />
              <YAxis tick={{ fill: 'var(--text-2)', fontSize: 10 }} allowDecimals={false} />
              <Tooltip contentStyle={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 8 }} />
              <Line type="monotone" dataKey="count" stroke="var(--blue-l)" strokeWidth={2} dot={{ fill: 'var(--blue-l)', r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity pie */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <AlertTriangle size={16} color="var(--high)" />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Severity Distribution</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <ResponsiveContainer width={160} height={160}>
              <PieChart>
                <Pie data={sevData} dataKey="value" cx="50%" cy="50%" innerRadius={45} outerRadius={70}>
                  {sevData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {sevData.map(d => (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: d.color }} />
                  <span style={{ fontSize: 12, textTransform: 'capitalize', color: 'var(--text-2)' }}>{d.name}</span>
                  <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text)', marginLeft: 'auto' }}>{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Provider bar */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <Cloud size={16} color="var(--cyan)" />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Findings by Provider</span>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={provData} layout="vertical">
              <XAxis type="number" tick={{ fill: 'var(--text-2)', fontSize: 10 }} />
              <YAxis type="category" dataKey="name" width={50} tick={{ fill: 'var(--text-2)', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 8 }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {provData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Family bar */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <BookOpen size={16} color="var(--blue-l)" />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Top Check Families</span>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={famData} layout="vertical">
              <XAxis type="number" tick={{ fill: 'var(--text-2)', fontSize: 10 }} />
              <YAxis type="category" dataKey="name" width={100} tick={{ fill: 'var(--text-2)', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 8 }} />
              <Bar dataKey="value" fill="var(--blue)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top services and risky accounts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 14 }}>Top Services by Findings</div>
          {(stats.top_services || []).slice(0, 8).map((s: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span className="mono" style={{ color: 'var(--text-2)' }}>{s.service}</span>
              <span style={{ color: 'var(--white)', fontFamily: 'var(--font-mono)' }}>{s.count}</span>
            </div>
          ))}
        </div>
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 14 }}>Top Risky Accounts</div>
          {(stats.top_risky_accounts || []).slice(0, 8).map((a: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <span className="mono truncate" style={{ color: 'var(--text-2)', maxWidth: '70%' }}>{a.account}</span>
              <span style={{ color: 'var(--white)', fontFamily: 'var(--font-mono)' }}>{a.count}</span>
            </div>
          ))}
          {(stats.top_risky_accounts || []).length === 0 && <p style={{ color: 'var(--text-2)', fontSize: 12 }}>No data yet.</p>}
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, color, icon }: { label: string; value: number; color: string; icon?: React.ReactNode }) {
  return (
    <div className="card stat-card">
      {icon && <div style={{ color, marginBottom: 6 }}>{icon}</div>}
      <div className="stat-value" style={{ color }}>{(value ?? 0).toLocaleString()}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

function LoadingState() {
  return (
    <div style={{ padding: 32, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {[...Array(3)].map((_, i) => (
        <div key={i} style={{ height: 100, background: 'var(--surface)', borderRadius: 'var(--radius-lg)', opacity: 0.5 }} />
      ))}
    </div>
  )
}
