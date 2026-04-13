import React, { useEffect, useState, useCallback } from 'react'
import { Search, Filter, ChevronDown, X, ExternalLink, EyeOff } from 'lucide-react'
import api from '../utils/api'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
const PROVIDERS = ['aws', 'azure', 'gcp', 'ibm', 'oci']
const STATUSES = ['open', 'resolved', 'suppressed', 'risk_accepted', 'false_positive']

export default function Findings() {
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pages, setPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<any>(null)
  const [suppressTarget, setSuppressTarget] = useState<any>(null)

  const [filters, setFilters] = useState({
    provider: '', severity: '', status: 'open', family: '', service: '', search: ''
  })

  const load = useCallback(() => {
    setLoading(true)
    api.findings({ ...filters, page, page_size: 50 })
      .then(r => { setItems(r.items); setTotal(r.total); setPages(r.pages); setLoading(false) })
      .catch(() => setLoading(false))
  }, [filters, page])

  useEffect(() => { load() }, [load])

  const setFilter = (k: string, v: string) => {
    setFilters(f => ({ ...f, [k]: v }))
    setPage(1)
  }

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 2 }}>Findings</h1>
          <p style={{ color: 'var(--text-2)', fontSize: 13 }}>{total.toLocaleString()} findings found</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 16, padding: '14px 16px' }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: '1 1 200px' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-2)' }} />
            <input className="input" style={{ paddingLeft: 30 }} placeholder="Search findings..."
              value={filters.search} onChange={e => setFilter('search', e.target.value)} />
          </div>
          <select className="input" style={{ flex: '0 0 130px' }} value={filters.severity} onChange={e => setFilter('severity', e.target.value)}>
            <option value="">All Severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select className="input" style={{ flex: '0 0 120px' }} value={filters.provider} onChange={e => setFilter('provider', e.target.value)}>
            <option value="">All Providers</option>
            {PROVIDERS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
          <select className="input" style={{ flex: '0 0 120px' }} value={filters.status} onChange={e => setFilter('status', e.target.value)}>
            <option value="">All Statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
          </select>
          {Object.values(filters).some(Boolean) && (
            <button className="btn btn-ghost btn-sm" onClick={() => { setFilters({ provider: '', severity: '', status: 'open', family: '', service: '', search: '' }); setPage(1) }}>
              <X size={12} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Provider</th>
                <th>Service</th>
                <th>Resource</th>
                <th>Status</th>
                <th>First Seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading...</td></tr>
              ) : items.length === 0 ? (
                <tr><td colSpan={8} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>No findings match current filters.</td></tr>
              ) : items.map(f => (
                <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(f)}>
                  <td><span className={`badge badge-${f.severity}`}>{f.severity}</span></td>
                  <td style={{ color: 'var(--text)', maxWidth: 320 }}>
                    <div className="truncate" style={{ fontWeight: 500 }}>{f.title}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>{f.check_id}</div>
                  </td>
                  <td><span className={`provider-${f.provider}`} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700 }}>{f.provider?.toUpperCase()}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>{f.service}</td>
                  <td style={{ maxWidth: 200 }}>
                    <div className="truncate mono" style={{ fontSize: 11 }}>{f.resource_display_name || f.native_id}</div>
                  </td>
                  <td><span className={`badge badge-${f.status}`}>{f.status}</span></td>
                  <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{f.first_seen?.slice(0, 10)}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <button className="btn btn-ghost btn-sm" title="Suppress" onClick={() => setSuppressTarget(f)}>
                      <EyeOff size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {pages > 1 && (
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Page {page} of {pages} — {total.toLocaleString()} total</span>
            <Pagination page={page} pages={pages} onPage={setPage} />
          </div>
        )}
      </div>

      {selected && <FindingModal finding={selected} onClose={() => setSelected(null)} onSuppress={() => { setSuppressTarget(selected); setSelected(null) }} />}
      {suppressTarget && <SuppressModal finding={suppressTarget} onClose={() => setSuppressTarget(null)} onDone={() => { setSuppressTarget(null); load() }} />}
    </div>
  )
}

function FindingModal({ finding: f, onClose, onSuppress }: { finding: any; onClose: () => void; onSuppress: () => void }) {
  const nativeId = f.arn || f.azure_resource_id || f.gcp_resource_name || f.ibm_crn || f.oci_ocid || f.native_id

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className={`badge badge-${f.severity}`}>{f.severity}</span>
            <span style={{ fontWeight: 600, fontSize: 15, color: 'var(--white)' }}>{f.title}</span>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-ghost btn-sm" onClick={onSuppress}><EyeOff size={13} /> Suppress</button>
            <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={14} /></button>
          </div>
        </div>
        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Resource identifiers */}
          <Section title="Resource Identifiers">
            <Row label="Provider" value={<span className={`provider-${f.provider}`} style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{f.provider?.toUpperCase()}</span>} />
            <Row label="Account / Project" value={f.account_context} mono />
            <Row label="Region" value={f.region} mono />
            <Row label="Service" value={f.service} mono />
            <Row label="Resource Type" value={f.resource_type} mono />
            <Row label="Display Name" value={f.resource_display_name} />
            <Row label="Native Identifier" value={nativeId} mono breakAll />
            <Row label="Universal Resource Name (URN)" value={f.universal_resource_name} mono breakAll />
          </Section>

          <Section title="Finding Details">
            <Row label="Check ID" value={f.check_id} mono />
            <Row label="Family" value={f.family} />
            <Row label="Status" value={<span className={`badge badge-${f.status}`}>{f.status}</span>} />
            <Row label="First Seen" value={f.first_seen?.slice(0, 19)} mono />
            <Row label="Last Seen" value={f.last_seen?.slice(0, 19)} mono />
          </Section>

          <Section title="Description">
            <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.7 }}>{f.description}</p>
          </Section>

          <Section title="Remediation">
            <p style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7, background: 'rgba(37,99,235,0.08)', padding: '10px 12px', borderRadius: 6, borderLeft: '3px solid var(--blue)' }}>{f.remediation}</p>
          </Section>

          {(f.compliance_frameworks || []).length > 0 && (
            <Section title="Compliance Frameworks">
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {f.compliance_frameworks.filter(Boolean).map((fw: string, i: number) => (
                  <span key={i} style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 6, padding: '3px 8px', fontSize: 12, color: 'var(--cyan)' }}>{fw}</span>
                ))}
              </div>
            </Section>
          )}

          {f.evidence && Object.keys(f.evidence).length > 0 && (
            <Section title="Evidence">
              <pre className="code-block" style={{ fontSize: 11 }}>{JSON.stringify(f.evidence, null, 2)}</pre>
            </Section>
          )}
        </div>
      </div>
    </div>
  )
}

function SuppressModal({ finding: f, onClose, onDone }: { finding: any; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('')
  const [riskAccepted, setRiskAccepted] = useState(false)
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    if (!reason.trim()) return
    setSaving(true)
    try {
      await api.suppressFinding(f.id, { reason, suppressed_by: 'user', risk_accepted: riskAccepted })
      onDone()
    } catch (e) {
      setSaving(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span style={{ fontWeight: 600 }}>Suppress Finding</span>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={14} /></button>
        </div>
        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <p style={{ fontSize: 13, color: 'var(--text-2)' }}>{f.title}</p>
          <div>
            <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 6 }}>Suppression Reason *</label>
            <textarea className="input" style={{ minHeight: 80, resize: 'vertical' }} value={reason} onChange={e => setReason(e.target.value)} placeholder="Explain why this finding is being suppressed..." />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
            <input type="checkbox" checked={riskAccepted} onChange={e => setRiskAccepted(e.target.checked)} />
            Mark as Risk Accepted (instead of suppressed)
          </label>
          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" onClick={submit} disabled={saving || !reason.trim()}>
              {saving ? 'Saving...' : 'Confirm Suppression'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-2)', marginBottom: 8 }}>{title}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>{children}</div>
    </div>
  )
}

function Row({ label, value, mono, breakAll }: { label: string; value: any; mono?: boolean; breakAll?: boolean }) {
  if (!value) return null
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', fontSize: 13 }}>
      <span style={{ minWidth: 180, color: 'var(--text-2)', flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'var(--font-mono)' : undefined, fontSize: mono ? 12 : 13, color: 'var(--text)', wordBreak: breakAll ? 'break-all' : undefined }}>{value}</span>
    </div>
  )
}

export function Pagination({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  const nums: (number | '...')[] = []
  if (pages <= 7) {
    for (let i = 1; i <= pages; i++) nums.push(i)
  } else {
    nums.push(1)
    if (page > 3) nums.push('...')
    for (let i = Math.max(2, page - 1); i <= Math.min(pages - 1, page + 1); i++) nums.push(i)
    if (page < pages - 2) nums.push('...')
    nums.push(pages)
  }
  return (
    <div className="pagination">
      <button className="page-btn" disabled={page === 1} onClick={() => onPage(page - 1)}>←</button>
      {nums.map((n, i) => n === '...'
        ? <span key={`e${i}`} style={{ color: 'var(--text-2)', padding: '0 4px' }}>…</span>
        : <button key={n} className={`page-btn${page === n ? ' active' : ''}`} onClick={() => onPage(n as number)}>{n}</button>
      )}
      <button className="page-btn" disabled={page === pages} onClick={() => onPage(page + 1)}>→</button>
    </div>
  )
}
