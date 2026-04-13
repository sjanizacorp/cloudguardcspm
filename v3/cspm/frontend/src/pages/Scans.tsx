import React, { useEffect, useState, useRef } from 'react'
import { Play, RefreshCw, CheckCircle, XCircle, Clock, Plus, ChevronDown, ChevronUp, Info, Wifi } from 'lucide-react'
import { Pagination } from './Findings'
import api from '../utils/api'

const PROVIDERS = ['aws','azure','gcp','ibm','oci']
const CRED_TYPES = ['env','profile','role','file','workload_identity']

const CRED_HINTS: Record<string, { fields: string[]; hint: string; envVars: string }> = {
  aws: {
    fields: ['Account ID'],
    hint: 'Reads AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY from environment.',
    envVars: 'AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION',
  },
  azure: {
    fields: ['Subscription ID'],
    hint: 'Reads AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET from environment.',
    envVars: 'AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID',
  },
  gcp: {
    fields: ['Project ID'],
    hint: 'Reads GOOGLE_APPLICATION_CREDENTIALS (path to service account JSON) from environment.',
    envVars: 'GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_CLOUD_PROJECT',
  },
  ibm: {
    fields: ['IBM Account ID'],
    hint: 'Reads IBMCLOUD_API_KEY from environment.',
    envVars: 'IBMCLOUD_API_KEY',
  },
  oci: {
    fields: ['Tenancy OCID'],
    hint: 'Reads from ~/.oci/config (OCI CLI config file).',
    envVars: '~/.oci/config',
  },
}

export default function Scans() {
  const [runs, setRuns] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [connections, setConnections] = useState<any[]>([])
  const [selected, setSelected] = useState<string[]>([])
  const [scanning, setScanning] = useState(false)
  const [showAddConn, setShowAddConn] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = () => {
    setLoading(true)
    api.scans({ page, page_size: 50 })
      .then(r => { setRuns(r.items); setTotal(r.total); setPages(r.pages); setLoading(false) })
      .catch(() => setLoading(false))
  }
  const loadConns = () =>
    api.connections({ page_size: 100 }).then(r => setConnections(r.items)).catch(() => {})

  useEffect(() => { load(); loadConns() }, [page])

  useEffect(() => {
    const hasRunning = runs.some(r => r.status === 'running' || r.status === 'pending')
    if (hasRunning && !pollRef.current) {
      pollRef.current = setInterval(() => { load(); loadConns() }, 3000)
    } else if (!hasRunning && pollRef.current) {
      clearInterval(pollRef.current); pollRef.current = null
    }
    return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null } }
  }, [runs])

  const startScan = async () => {
    if (!selected.length) return
    setScanning(true)
    try {
      await api.startScan({ connection_ids: selected, name: 'Manual scan' })
      setSelected([])
      setTimeout(load, 800)
    } catch (e: any) { alert(`Error: ${e.message}`) }
    setScanning(false)
  }

  const StatusIcon = ({ s }: { s: string }) => {
    if (s === 'completed') return <CheckCircle size={14} color="var(--low)" />
    if (s === 'failed')    return <XCircle size={14} color="var(--crit)" />
    if (s === 'running')   return <RefreshCw size={14} color="var(--blue-l)" style={{ animation: 'spin 1.2s linear infinite' }} />
    return <Clock size={14} color="var(--text-2)" />
  }

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 2 }}>Scans</h1>
        <p style={{ color: 'var(--text-2)', fontSize: 13 }}>Trigger security scans against your cloud connections</p>
      </div>

      {/* Add connection inline panel */}
      <div className="card" style={{ marginBottom: 16, border: '1px solid rgba(37,99,235,0.3)', background: 'rgba(37,99,235,0.05)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: showAddConn ? 16 : 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Wifi size={16} color="var(--blue-l)" />
            <div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>Cloud Connections & Credentials</div>
              <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>
                Add a connection, then select it below to scan. Without real credentials, scans run in <strong style={{ color: 'var(--cyan)' }}>demo mode</strong> against seeded assets.
              </div>
            </div>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => setShowAddConn(v => !v)}>
            {showAddConn ? <ChevronUp size={13} /> : <><Plus size={13} /> Add Connection</>}
          </button>
        </div>
        {showAddConn && (
          <AddConnectionForm onDone={() => { setShowAddConn(false); loadConns() }} />
        )}
      </div>

      {/* Launch scan */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12 }}>Launch Scan</div>
        {connections.length === 0 ? (
          <div style={{ padding: '16px 0', color: 'var(--text-2)', fontSize: 13 }}>
            No connections yet. Add one above, then scan. <br />
            <span style={{ color: 'var(--cyan)', fontSize: 12 }}>
              Tip: With demo data enabled, clicking scan on any connection will run immediately in demo mode — no cloud credentials required.
            </span>
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
            {connections.map(c => (
              <label
                key={c.id}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
                  padding: '8px 14px', border: '1px solid',
                  borderColor: selected.includes(c.id) ? 'var(--blue)' : 'var(--border)',
                  background: selected.includes(c.id) ? 'rgba(37,99,235,0.15)' : 'var(--navy-2)',
                  borderRadius: 8, fontSize: 13, transition: 'all 0.15s',
                }}
              >
                <input
                  type="checkbox"
                  style={{ display: 'none' }}
                  checked={selected.includes(c.id)}
                  onChange={e => setSelected(s => e.target.checked ? [...s, c.id] : s.filter(id => id !== c.id))}
                />
                <span className={`provider-${c.provider}`} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700 }}>
                  {c.provider?.toUpperCase()}
                </span>
                <span style={{ color: 'var(--text)' }}>{c.name}</span>
                {!c.last_scan_at && (
                  <span style={{ fontSize: 10, color: 'var(--text-2)', background: 'var(--navy-3)', padding: '1px 6px', borderRadius: 4 }}>
                    never scanned
                  </span>
                )}
                {c.last_scan_at && (
                  <span style={{ fontSize: 10, color: 'var(--text-2)' }}>
                    last: {c.last_scan_at.slice(0, 10)}
                  </span>
                )}
              </label>
            ))}
          </div>
        )}

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            className="btn btn-primary"
            onClick={startScan}
            disabled={scanning || selected.length === 0}
            style={{ minWidth: 120 }}
          >
            <Play size={14} />
            {scanning ? 'Starting...' : `Scan ${selected.length > 0 ? `(${selected.length})` : ''}`}
          </button>
          {selected.length > 0 && (
            <button className="btn btn-ghost btn-sm" onClick={() => setSelected([])}>Clear</button>
          )}
        </div>

        {/* Demo mode info box */}
        <div style={{ marginTop: 14, padding: '10px 14px', background: 'rgba(6,182,212,0.07)', border: '1px solid rgba(6,182,212,0.2)', borderRadius: 8 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            <Info size={14} color="var(--cyan)" style={{ marginTop: 2, flexShrink: 0 }} />
            <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
              <strong style={{ color: 'var(--cyan)' }}>Demo mode:</strong> If cloud credentials are not configured in your <code style={{ fontFamily: 'var(--font-mono)' }}>.env</code> file, scans run against the seeded demo assets and produce real findings immediately. To scan live infrastructure, set the appropriate environment variables for your provider and restart the application. See the Configuration Manual for details.
            </div>
          </div>
        </div>
      </div>

      {/* Scan history */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>Scan History</span>
          <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={12} /> Refresh</button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Connection</th>
                <th>Mode</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Assets</th>
                <th>Checks</th>
                <th>New Findings</th>
                <th>Resolved</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading...</td></tr>
              ) : runs.length === 0 ? (
                <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>No scans yet. Select a connection above and click Scan.</td></tr>
              ) : runs.map(r => {
                const duration = r.started_at && r.completed_at
                  ? Math.round((new Date(r.completed_at).getTime() - new Date(r.started_at).getTime()) / 1000)
                  : null
                const connName = connections.find(c => c.id === r.connection_id)?.name || r.connection_id.slice(0, 20)
                const isDemo = r.log?.includes('Demo scan') || r.log?.includes('demo')
                return (
                  <tr key={r.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <StatusIcon s={r.status} />
                        <span style={{ fontSize: 12 }}>{r.status}</span>
                      </div>
                    </td>
                    <td style={{ color: 'var(--text)', fontSize: 12 }}>{connName}</td>
                    <td>
                      <span style={{ fontSize: 11, padding: '2px 7px', borderRadius: 4, background: isDemo ? 'rgba(6,182,212,0.12)' : 'rgba(34,197,94,0.12)', color: isDemo ? 'var(--cyan)' : 'var(--low)' }}>
                        {isDemo ? 'demo' : 'live'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>{r.started_at?.slice(0, 16) || r.created_at?.slice(0, 16)}</td>
                    <td style={{ fontSize: 12 }}>{duration != null ? `${duration}s` : '—'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{r.assets_discovered}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{r.checks_run}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: r.findings_created > 0 ? 'var(--high)' : 'var(--text-2)' }}>{r.findings_created}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: r.findings_resolved > 0 ? 'var(--low)' : 'var(--text-2)' }}>{r.findings_resolved}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        {pages > 1 && (
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'flex-end' }}>
            <Pagination page={page} pages={pages} onPage={setPage} />
          </div>
        )}
      </div>

      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  )
}

// ─── Inline Add Connection Form ───────────────────────────────────────────────
function AddConnectionForm({ onDone }: { onDone: () => void }) {
  const [form, setForm] = useState({
    name: '', provider: 'aws',
    account_id: '', subscription_id: '', project_id: '', tenancy_id: '', ibm_account_id: '',
    credential_type: 'env', credential_ref: '', regions: '', notes: '',
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))
  const hint = CRED_HINTS[form.provider]

  const submit = async () => {
    if (!form.name.trim()) { setError('Connection name is required.'); return }
    setSaving(true); setError('')
    try {
      await api.createConnection({
        ...form,
        regions: form.regions ? form.regions.split(',').map(r => r.trim()).filter(Boolean) : [],
      })
      onDone()
    } catch (e: any) { setError(e.message); setSaving(false) }
  }

  return (
    <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
      {error && (
        <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(239,68,68,0.1)', color: 'var(--crit)', borderRadius: 6, fontSize: 12 }}>
          {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        <Field label="Connection Name *">
          <input className="input" value={form.name} onChange={e => set('name', e.target.value)} placeholder="e.g. Production AWS" />
        </Field>
        <Field label="Cloud Provider *">
          <select className="input" value={form.provider} onChange={e => set('provider', e.target.value)}>
            {PROVIDERS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
        </Field>

        {form.provider === 'aws'   && <Field label="AWS Account ID"><input className="input" value={form.account_id} onChange={e => set('account_id', e.target.value)} placeholder="123456789012" /></Field>}
        {form.provider === 'azure' && <Field label="Subscription ID"><input className="input" value={form.subscription_id} onChange={e => set('subscription_id', e.target.value)} placeholder="aaaa-bbbb-cccc-dddd" /></Field>}
        {form.provider === 'gcp'   && <Field label="Project ID"><input className="input" value={form.project_id} onChange={e => set('project_id', e.target.value)} placeholder="my-project-id" /></Field>}
        {form.provider === 'oci'   && <Field label="Tenancy OCID"><input className="input" value={form.tenancy_id} onChange={e => set('tenancy_id', e.target.value)} placeholder="ocid1.tenancy.oc1.." /></Field>}
        {form.provider === 'ibm'   && <Field label="IBM Account ID"><input className="input" value={form.ibm_account_id} onChange={e => set('ibm_account_id', e.target.value)} placeholder="ibm-account-id" /></Field>}

        <Field label="Credential Type">
          <select className="input" value={form.credential_type} onChange={e => set('credential_type', e.target.value)}>
            {CRED_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </Field>

        <Field
          label={form.credential_type === 'role' ? 'Role ARN' : form.credential_type === 'profile' ? 'Profile Name' : form.credential_type === 'file' ? 'File Path' : 'Credential Ref (optional)'}
          hint={form.credential_type === 'env' ? `Leave blank — credentials read from env vars: ${hint.envVars}` : undefined}
        >
          <input
            className="input"
            value={form.credential_ref}
            onChange={e => set('credential_ref', e.target.value)}
            placeholder={
              form.credential_type === 'role'    ? 'arn:aws:iam::123456789012:role/CloudGuardReadOnly' :
              form.credential_type === 'profile' ? 'prod-readonly' :
              form.credential_type === 'file'    ? '/path/to/service-account.json' : ''
            }
          />
        </Field>

        <Field label="Regions (comma-separated, blank = all)">
          <input className="input" value={form.regions} onChange={e => set('regions', e.target.value)} placeholder="us-east-1, eu-west-1" />
        </Field>
      </div>

      {/* Credential hint box */}
      <div style={{ marginBottom: 12, padding: '10px 14px', background: 'rgba(6,182,212,0.06)', border: '1px solid rgba(6,182,212,0.15)', borderRadius: 8, fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--cyan)' }}>{form.provider.toUpperCase()} credentials:</strong> {hint.hint}
        <br />
        <span>Required env vars: </span>
        <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text)', fontSize: 11 }}>{hint.envVars}</code>
        <br />
        <span style={{ color: 'var(--text-2)' }}>Set these in your <code style={{ fontFamily: 'var(--font-mono)' }}>.env</code> file and restart. Without them, scans run in demo mode.</span>
      </div>

      <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
        <button className="btn btn-ghost" onClick={onDone}>Cancel</button>
        <button className="btn btn-primary" onClick={submit} disabled={saving}>
          {saving ? 'Saving...' : 'Add Connection'}
        </button>
      </div>
    </div>
  )
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 5 }}>{label}</label>
      {children}
      {hint && <p style={{ fontSize: 11, color: 'var(--slate)', marginTop: 4 }}>{hint}</p>}
    </div>
  )
}
