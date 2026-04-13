import React, { useEffect, useState } from 'react'
import { Plus, Trash2, Play, X, Wifi } from 'lucide-react'
import api from '../utils/api'

const PROVIDERS = ['aws', 'azure', 'gcp', 'ibm', 'oci']
const CRED_TYPES = ['env', 'profile', 'role', 'file', 'workload_identity']

export default function Connections() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [scanTarget, setScanTarget] = useState<any>(null)
  const [scanning, setScanning] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    api.connections({ page_size: 100 }).then(r => { setItems(r.items); setLoading(false) }).catch(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const deleteConn = async (id: string) => {
    if (!confirm('Delete this connection?')) return
    await api.deleteConnection(id)
    load()
  }

  const startScan = async (conn: any) => {
    setScanning(conn.id)
    try {
      await api.startScan({ connection_ids: [conn.id] })
      alert(`Scan started for ${conn.name}. Check the Scans page for progress.`)
    } catch (e: any) {
      alert(`Scan failed: ${e.message}`)
    }
    setScanning(null)
  }

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 2 }}>Cloud Connections</h1>
          <p style={{ color: 'var(--text-2)', fontSize: 13 }}>Manage provider credentials and accounts</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(true)}><Plus size={14} /> Add Connection</button>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Provider</th>
              <th>Account / Project</th>
              <th>Regions</th>
              <th>Credential Type</th>
              <th>Last Scan</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading...</td></tr>
            ) : items.length === 0 ? (
              <tr><td colSpan={8} style={{ padding: 40, textAlign: 'center' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                  <Wifi size={40} color="var(--border)" />
                  <p style={{ color: 'var(--text-2)' }}>No connections configured. Add one to start scanning.</p>
                  <button className="btn btn-primary" onClick={() => setShowForm(true)}><Plus size={14} /> Add Connection</button>
                </div>
              </td></tr>
            ) : items.map(c => (
              <tr key={c.id}>
                <td style={{ color: 'var(--text)', fontWeight: 500 }}>{c.name}</td>
                <td><span className={`provider-${c.provider}`} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700 }}>{c.provider?.toUpperCase()}</span></td>
                <td className="mono" style={{ fontSize: 11 }}>{c.account_id || c.subscription_id || c.project_id || c.tenancy_id || c.ibm_account_id || '—'}</td>
                <td style={{ fontSize: 12 }}>{(c.regions || []).slice(0, 3).join(', ')}{c.regions?.length > 3 ? ` +${c.regions.length - 3}` : ''}</td>
                <td className="mono" style={{ fontSize: 11 }}>{c.credential_type || 'env'}</td>
                <td style={{ fontSize: 12 }}>{c.last_scan_at ? c.last_scan_at.slice(0, 16) : <span style={{ color: 'var(--text-2)' }}>Never</span>}</td>
                <td><span style={{ fontSize: 11, color: c.enabled ? 'var(--low)' : 'var(--text-2)' }}>● {c.enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="btn btn-primary btn-sm" onClick={() => startScan(c)} disabled={scanning === c.id}>
                      <Play size={11} /> {scanning === c.id ? 'Starting...' : 'Scan'}
                    </button>
                    <button className="btn btn-danger btn-sm" onClick={() => deleteConn(c.id)}><Trash2 size={11} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showForm && <ConnectionForm onClose={() => { setShowForm(false); load() }} />}
    </div>
  )
}

function ConnectionForm({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({
    name: '', provider: 'aws', alias: '',
    account_id: '', subscription_id: '', project_id: '', tenancy_id: '', ibm_account_id: '',
    credential_type: 'env', credential_ref: '', regions: '', notes: '',
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  const submit = async () => {
    if (!form.name || !form.provider) { setError('Name and provider are required.'); return }
    setSaving(true)
    try {
      await api.createConnection({
        ...form,
        regions: form.regions ? form.regions.split(',').map(r => r.trim()).filter(Boolean) : [],
      })
      onClose()
    } catch (e: any) { setError(e.message); setSaving(false) }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span style={{ fontWeight: 600 }}>Add Cloud Connection</span>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={14} /></button>
        </div>
        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          {error && <div style={{ color: 'var(--crit)', fontSize: 12, background: 'rgba(239,68,68,0.1)', padding: '8px 12px', borderRadius: 6 }}>{error}</div>}

          <FormField label="Connection Name *">
            <input className="input" value={form.name} onChange={e => set('name', e.target.value)} placeholder="e.g. Production AWS" />
          </FormField>
          <FormField label="Cloud Provider *">
            <select className="input" value={form.provider} onChange={e => set('provider', e.target.value)}>
              {PROVIDERS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
            </select>
          </FormField>

          {form.provider === 'aws' && <FormField label="AWS Account ID"><input className="input" value={form.account_id} onChange={e => set('account_id', e.target.value)} placeholder="123456789012" /></FormField>}
          {form.provider === 'azure' && <FormField label="Subscription ID"><input className="input" value={form.subscription_id} onChange={e => set('subscription_id', e.target.value)} placeholder="aaaa-bbbb-cccc-dddd" /></FormField>}
          {form.provider === 'gcp' && <FormField label="Project ID"><input className="input" value={form.project_id} onChange={e => set('project_id', e.target.value)} placeholder="my-project-id" /></FormField>}
          {form.provider === 'oci' && <FormField label="Tenancy OCID"><input className="input" value={form.tenancy_id} onChange={e => set('tenancy_id', e.target.value)} placeholder="ocid1.tenancy.oc1..." /></FormField>}
          {form.provider === 'ibm' && <FormField label="IBM Account ID"><input className="input" value={form.ibm_account_id} onChange={e => set('ibm_account_id', e.target.value)} placeholder="ibm-account-id" /></FormField>}

          <FormField label="Credential Type">
            <select className="input" value={form.credential_type} onChange={e => set('credential_type', e.target.value)}>
              {CRED_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </FormField>
          <FormField label="Credential Ref (optional)" hint="For 'role': ARN. For 'profile': profile name. For 'file': path. Leave blank to use env vars.">
            <input className="input" value={form.credential_ref} onChange={e => set('credential_ref', e.target.value)} placeholder="e.g. arn:aws:iam::123:role/CloudGuardReadOnly" />
          </FormField>
          <FormField label="Regions (comma-separated, blank = all)">
            <input className="input" value={form.regions} onChange={e => set('regions', e.target.value)} placeholder="us-east-1, us-west-2, eu-west-1" />
          </FormField>
          <FormField label="Notes">
            <input className="input" value={form.notes} onChange={e => set('notes', e.target.value)} placeholder="Optional notes" />
          </FormField>

          <div style={{ background: 'rgba(37,99,235,0.08)', border: '1px solid rgba(37,99,235,0.2)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: 'var(--text-2)' }}>
            ⚠️ Credentials are never stored in plaintext. Use credential_type=env to read from environment variables. See the Configuration Manual for secure setup.
          </div>

          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" onClick={submit} disabled={saving}>{saving ? 'Saving...' : 'Add Connection'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function FormField({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 5 }}>{label}</label>
      {children}
      {hint && <p style={{ fontSize: 11, color: 'var(--slate)', marginTop: 4 }}>{hint}</p>}
    </div>
  )
}
