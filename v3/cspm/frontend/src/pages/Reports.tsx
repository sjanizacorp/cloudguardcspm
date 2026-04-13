import React, { useEffect, useState } from 'react'
import { FileText, Download, RefreshCw, Plus } from 'lucide-react'
import api from '../utils/api'

const REPORT_TYPES = [
  { id: 'executive', label: 'Executive Summary', desc: 'High-level KPIs, severity breakdown, provider distribution and top risky accounts.' },
  { id: 'technical', label: 'Technical Findings', desc: 'Full findings list with all resource identifiers, evidence, and remediation steps.' },
  { id: 'compliance', label: 'Compliance Report', desc: 'Findings grouped by compliance framework (CIS, NIST, SOC 2, PCI DSS).' },
  { id: 'inventory', label: 'Asset Inventory', desc: 'Full asset inventory with native resource identifiers and URNs.' },
  { id: 'catalog', label: 'Check Catalog', desc: 'Complete catalog of all security checks with provenance and metadata.' },
]

const PROVIDERS = ['', 'aws', 'azure', 'gcp', 'ibm', 'oci']
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'informational']

export default function Reports() {
  const [reports, setReports] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState<string | null>(null)
  const [filters, setFilters] = useState({ provider: '', severity: '' })

  const load = () => {
    setLoading(true)
    api.reports().then(r => { setReports(r); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  // Poll while reports are generating
  useEffect(() => {
    const hasGenerating = reports.some(r => r.status === 'pending' || r.status === 'generating')
    if (!hasGenerating) return
    const t = setTimeout(load, 3000)
    return () => clearTimeout(t)
  }, [reports])

  const generate = async (reportType: string) => {
    setGenerating(reportType)
    const activeFilters: Record<string, string> = {}
    if (filters.provider) activeFilters.provider = filters.provider
    if (filters.severity) activeFilters.severity = filters.severity
    try {
      await api.createReport({ report_type: reportType, filters: activeFilters })
      setTimeout(load, 500)
    } catch (e: any) {
      alert(`Error: ${e.message}`)
    }
    setGenerating(null)
  }

  const StatusBadge = ({ status }: { status: string }) => {
    const colors: Record<string, string> = {
      completed: 'var(--low)', pending: 'var(--med)', generating: 'var(--blue-l)', failed: 'var(--crit)'
    }
    return <span style={{ fontSize: 11, color: colors[status] || 'var(--text-2)' }}>● {status}</span>
  }

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 2 }}>Reports</h1>
        <p style={{ color: 'var(--text-2)', fontSize: 13 }}>Generate and download PDF security reports</p>
      </div>

      {/* Filter row */}
      <div className="card" style={{ marginBottom: 16, padding: '14px 16px' }}>
        <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 10 }}>Report Filters (applied to new reports)</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="input" style={{ maxWidth: 160 }} value={filters.provider} onChange={e => setFilters(f => ({ ...f, provider: e.target.value }))}>
            <option value="">All Providers</option>
            {PROVIDERS.filter(Boolean).map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
          <select className="input" style={{ maxWidth: 160 }} value={filters.severity} onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}>
            <option value="">All Severities</option>
            {SEVERITIES.filter(Boolean).map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>
      </div>

      {/* Report type cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14, marginBottom: 24 }}>
        {REPORT_TYPES.map(rt => (
          <div key={rt.id} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              <FileText size={20} color="var(--blue-l)" style={{ marginTop: 2, flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--white)', marginBottom: 4 }}>{rt.label}</div>
                <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>{rt.desc}</div>
              </div>
            </div>
            <button
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center' }}
              disabled={generating === rt.id}
              onClick={() => generate(rt.id)}
            >
              <Plus size={13} /> {generating === rt.id ? 'Queuing...' : 'Generate PDF'}
            </button>
          </div>
        ))}
      </div>

      {/* Report history */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>Report History</span>
          <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={12} /> Refresh</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Filters</th>
              <th>Status</th>
              <th>Created</th>
              <th>Completed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading...</td></tr>
            ) : reports.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>No reports generated yet.</td></tr>
            ) : reports.map((r: any) => (
              <tr key={r.id}>
                <td style={{ color: 'var(--text)', textTransform: 'capitalize', fontWeight: 500 }}>{r.report_type}</td>
                <td style={{ fontSize: 11 }}>
                  {Object.entries(r.filters || {}).length > 0
                    ? Object.entries(r.filters).map(([k, v]) => `${k}=${v}`).join(', ')
                    : <span style={{ color: 'var(--text-2)' }}>none</span>}
                </td>
                <td><StatusBadge status={r.status} /></td>
                <td style={{ fontSize: 12 }}>{r.created_at?.slice(0, 16)}</td>
                <td style={{ fontSize: 12 }}>{r.completed_at?.slice(0, 16) || '—'}</td>
                <td>
                  {r.status === 'completed' && (
                    <a href={api.downloadReport(r.id)} target="_blank" rel="noopener noreferrer" className="btn btn-primary btn-sm">
                      <Download size={12} /> Download
                    </a>
                  )}
                  {(r.status === 'pending' || r.status === 'generating') && (
                    <span style={{ fontSize: 11, color: 'var(--blue-l)' }}>Generating...</span>
                  )}
                  {r.status === 'failed' && (
                    <span style={{ fontSize: 11, color: 'var(--crit)' }}>Failed</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 16, fontSize: 12, color: 'var(--text-2)', padding: '10px 14px', background: 'var(--surface)', borderRadius: 8, border: '1px solid var(--border)' }}>
        📄 PDF reports are generated server-side using ReportLab. Reports are stored in <code style={{ fontFamily: 'var(--font-mono)' }}>{'{REPORTS_DIR}'}</code> and expire after restart unless persisted to a volume.
      </div>
    </div>
  )
}
