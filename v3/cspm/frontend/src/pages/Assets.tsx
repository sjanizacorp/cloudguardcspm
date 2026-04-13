import React, { useEffect, useState, useCallback } from 'react'
import { Search, X, Database } from 'lucide-react'
import { Pagination } from './Findings'
import api from '../utils/api'

const PROVIDERS = ['aws', 'azure', 'gcp', 'ibm', 'oci']

export default function Assets() {
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pages, setPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<any>(null)
  const [assetFindings, setAssetFindings] = useState<any[]>([])

  const [filters, setFilters] = useState({ provider: '', service: '', resource_type: '', search: '' })

  const load = useCallback(() => {
    setLoading(true)
    api.assets({ ...filters, page, page_size: 50 })
      .then(r => { setItems(r.items); setTotal(r.total); setPages(r.pages); setLoading(false) })
      .catch(() => setLoading(false))
  }, [filters, page])

  useEffect(() => { load() }, [load])

  const openAsset = async (asset: any) => {
    setSelected(asset)
    const findings = await api.assetFindings(asset.id).catch(() => [])
    setAssetFindings(findings)
  }

  const setFilter = (k: string, v: string) => { setFilters(f => ({ ...f, [k]: v })); setPage(1) }

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 2 }}>Asset Inventory</h1>
        <p style={{ color: 'var(--text-2)', fontSize: 13 }}>{total.toLocaleString()} assets discovered</p>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 16, padding: '14px 16px' }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 200px' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-2)' }} />
            <input className="input" style={{ paddingLeft: 30 }} placeholder="Search by name or ID..."
              value={filters.search} onChange={e => setFilter('search', e.target.value)} />
          </div>
          <select className="input" style={{ flex: '0 0 120px' }} value={filters.provider} onChange={e => setFilter('provider', e.target.value)}>
            <option value="">All Providers</option>
            {PROVIDERS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
          <input className="input" style={{ flex: '0 0 140px' }} placeholder="Service (e.g. s3)" value={filters.service} onChange={e => setFilter('service', e.target.value)} />
          {Object.values(filters).some(Boolean) && (
            <button className="btn btn-ghost btn-sm" onClick={() => { setFilters({ provider: '', service: '', resource_type: '', search: '' }); setPage(1) }}>
              <X size={12} /> Clear
            </button>
          )}
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Service</th>
                <th>Type</th>
                <th>Region</th>
                <th>Display Name</th>
                <th>Universal Resource Name</th>
                <th>First Seen</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading...</td></tr>
              ) : items.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>No assets found.</td></tr>
              ) : items.map(a => (
                <tr key={a.id} style={{ cursor: 'pointer' }} onClick={() => openAsset(a)}>
                  <td><span className={`provider-${a.provider}`} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700 }}>{a.provider?.toUpperCase()}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>{a.service}</td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>{a.resource_type}</td>
                  <td style={{ fontSize: 12 }}>{a.region}</td>
                  <td style={{ color: 'var(--text)' }}>{a.display_name}</td>
                  <td className="mono" style={{ fontSize: 10, maxWidth: 300 }}>
                    <span className="truncate" style={{ display: 'block' }}>{a.universal_resource_name}</span>
                  </td>
                  <td style={{ fontSize: 11 }}>{a.first_seen?.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {pages > 1 && (
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Page {page} of {pages}</span>
            <Pagination page={page} pages={pages} onPage={setPage} />
          </div>
        )}
      </div>

      {selected && (
        <div className="modal-overlay" onClick={() => setSelected(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Database size={18} color="var(--blue-l)" />
                <span style={{ fontWeight: 600, color: 'var(--white)' }}>{selected.display_name || selected.native_id}</span>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelected(null)}><X size={14} /></button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                {[
                  ['Provider', <span className={`provider-${selected.provider}`} style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{selected.provider?.toUpperCase()}</span>],
                  ['Service', selected.service],
                  ['Resource Type', selected.resource_type],
                  ['Region', selected.region],
                  ['First Seen', selected.first_seen?.slice(0, 10)],
                  ['Last Seen', selected.last_seen?.slice(0, 10)],
                ].map(([k, v], i) => (
                  <div key={i} style={{ background: 'var(--navy-2)', borderRadius: 8, padding: '10px 14px' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>{k as string}</div>
                    <div style={{ fontSize: 13, color: 'var(--text)' }}>{v as any}</div>
                  </div>
                ))}
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-2)', marginBottom: 8, letterSpacing: '0.08em' }}>Native Resource Identifiers</div>
                {selected.arn && <IdRow label="ARN" value={selected.arn} />}
                {selected.azure_resource_id && <IdRow label="Azure Resource ID" value={selected.azure_resource_id} />}
                {selected.gcp_resource_name && <IdRow label="GCP Resource Name" value={selected.gcp_resource_name} />}
                {selected.ibm_crn && <IdRow label="IBM CRN" value={selected.ibm_crn} />}
                {selected.oci_ocid && <IdRow label="OCI OCID" value={selected.oci_ocid} />}
                <IdRow label="Universal Resource Name" value={selected.universal_resource_name} />
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-2)', marginBottom: 8, letterSpacing: '0.08em' }}>
                  Findings ({assetFindings.length})
                </div>
                {assetFindings.length === 0 ? (
                  <p style={{ color: 'var(--low)', fontSize: 13 }}>✓ No open findings for this asset.</p>
                ) : assetFindings.map((f: any) => (
                  <div key={f.id} style={{ padding: '8px 12px', background: 'var(--navy-2)', borderRadius: 8, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    <span style={{ fontSize: 13, color: 'var(--text)' }}>{f.title}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function IdRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'baseline' }}>
      <span style={{ fontSize: 11, color: 'var(--text-2)', minWidth: 160, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all', color: 'var(--cyan)' }}>{value}</span>
    </div>
  )
}
