import React, { useEffect, useState, useCallback } from 'react'
import { Search, Code2, X, BookOpen, ChevronRight, ExternalLink } from 'lucide-react'
import { Pagination } from './Findings'
import api from '../utils/api'

const PROVIDERS = ['aws', 'azure', 'gcp', 'ibm', 'oci']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']

export default function Checks() {
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pages, setPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [families, setFamilies] = useState<any[]>([])
  const [codeTarget, setCodeTarget] = useState<any>(null)
  const [codeData, setCodeData] = useState<any>(null)
  const [codeLoading, setCodeLoading] = useState(false)
  const [activeFamily, setActiveFamily] = useState('')

  const [filters, setFilters] = useState({ provider: '', severity: '', search: '', family: '' })

  const load = useCallback(() => {
    setLoading(true)
    api.checks({ ...filters, family: activeFamily || filters.family, page, page_size: 50 })
      .then(r => { setItems(r.items); setTotal(r.total); setPages(r.pages); setLoading(false) })
      .catch(() => setLoading(false))
  }, [filters, activeFamily, page])

  useEffect(() => { load() }, [load])
  useEffect(() => { api.checkFamilies().then(setFamilies).catch(() => {}) }, [])

  const viewCode = async (check: any) => {
    setCodeTarget(check)
    setCodeData(null)
    setCodeLoading(true)
    try {
      const data = await api.checkCode(check.check_id)
      setCodeData(data)
    } catch (e) {
      setCodeData({ error: 'Could not load check source.' })
    }
    setCodeLoading(false)
  }

  const setFilter = (k: string, v: string) => { setFilters(f => ({ ...f, [k]: v })); setPage(1) }

  return (
    <div style={{ padding: '24px 28px' }} className="fade-in">
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--white)', marginBottom: 2 }}>Check Catalog</h1>
        <p style={{ color: 'var(--text-2)', fontSize: 13 }}>{total.toLocaleString()} security checks across all providers</p>
      </div>

      <div style={{ display: 'flex', gap: 16 }}>
        {/* Family sidebar */}
        <div style={{ width: 220, flexShrink: 0 }}>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-2)' }}>
              Families
            </div>
            <div style={{ maxHeight: 500, overflowY: 'auto' }}>
              <button
                className="nav-link"
                style={{ borderRadius: 0, margin: 0, paddingLeft: 14 }}
                onClick={() => { setActiveFamily(''); setPage(1) }}
              >
                <BookOpen size={14} />
                <span style={{ flex: 1 }}>All Families</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{families.reduce((s, f) => s + f.count, 0)}</span>
              </button>
              {families.map((f: any) => (
                <button
                  key={f.family}
                  className={`nav-link${activeFamily === f.family ? ' active' : ''}`}
                  style={{ borderRadius: 0, margin: 0, paddingLeft: 14, fontSize: 12 }}
                  onClick={() => { setActiveFamily(f.family); setPage(1) }}
                >
                  <ChevronRight size={12} style={{ flexShrink: 0 }} />
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.family}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{f.count}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1 }}>
          {/* Filters */}
          <div className="card" style={{ marginBottom: 14, padding: '12px 14px' }}>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <div style={{ position: 'relative', flex: '1 1 180px' }}>
                <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-2)' }} />
                <input className="input" style={{ paddingLeft: 28 }} placeholder="Search checks..."
                  value={filters.search} onChange={e => setFilter('search', e.target.value)} />
              </div>
              <select className="input" style={{ flex: '0 0 120px' }} value={filters.provider} onChange={e => setFilter('provider', e.target.value)}>
                <option value="">All Providers</option>
                {PROVIDERS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
              </select>
              <select className="input" style={{ flex: '0 0 130px' }} value={filters.severity} onChange={e => setFilter('severity', e.target.value)}>
                <option value="">All Severities</option>
                {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>
            </div>
          </div>

          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Check ID</th>
                    <th>Name</th>
                    <th>Provider</th>
                    <th>Family</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Status</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan={8} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading...</td></tr>
                  ) : items.length === 0 ? (
                    <tr><td colSpan={8} style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>No checks match filters.</td></tr>
                  ) : items.map(c => (
                    <tr key={c.id}>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--cyan)' }}>{c.check_id}</td>
                      <td style={{ color: 'var(--text)', maxWidth: 280 }}>
                        <div style={{ fontWeight: 500, fontSize: 13 }}>{c.name}</div>
                      </td>
                      <td><span className={`provider-${c.provider}`} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700 }}>{c.provider?.toUpperCase()}</span></td>
                      <td style={{ fontSize: 12 }}>{c.family}</td>
                      <td><span className={`badge badge-${c.severity}`}>{c.severity}</span></td>
                      <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{c.source_vendor}</td>
                      <td>
                        <span style={{ fontSize: 11, color: c.status === 'implemented' ? 'var(--low)' : 'var(--med)' }}>
                          {c.status}
                        </span>
                      </td>
                      <td>
                        <button className="btn btn-ghost btn-sm" onClick={() => viewCode(c)} title="View Check Code">
                          <Code2 size={13} /> Code
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {pages > 1 && (
              <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Page {page} of {pages} — {total.toLocaleString()} checks</span>
                <Pagination page={page} pages={pages} onPage={setPage} />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Code Viewer Modal */}
      {codeTarget && (
        <div className="modal-overlay" onClick={() => { setCodeTarget(null); setCodeData(null) }}>
          <div className="modal" style={{ maxWidth: 900 }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Code2 size={18} color="var(--cyan)" />
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--white)', fontSize: 14 }}>{codeTarget.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{codeTarget.check_id}</div>
                </div>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => { setCodeTarget(null); setCodeData(null) }}><X size={14} /></button>
            </div>
            <div style={{ padding: 20 }}>
              {codeLoading ? (
                <div style={{ color: 'var(--text-2)', textAlign: 'center', padding: 32 }}>Loading check source...</div>
              ) : codeData?.error ? (
                <div style={{ color: 'var(--crit)' }}>{codeData.error}</div>
              ) : codeData ? (
                <CodeViewer data={codeData} check={codeTarget} />
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function CodeViewer({ data, check }: { data: any; check: any }) {
  const [tab, setTab] = useState<'code' | 'yaml' | 'meta' | 'tests'>('code')

  const tabs = [
    { id: 'code', label: 'Implementation', disabled: !data.implementation_code },
    { id: 'yaml', label: 'YAML Definition', disabled: !data.yaml_definition },
    { id: 'meta', label: 'Provenance', disabled: false },
    { id: 'tests', label: 'Test Cases', disabled: !data.test_cases?.length },
  ] as const

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Tabs */}
      <div style={{ display: 'flex', gap: 2, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
        {tabs.filter(t => !t.disabled).map(t => (
          <button key={t.id}
            onClick={() => setTab(t.id as any)}
            style={{
              padding: '7px 14px', fontSize: 12, fontWeight: 500, cursor: 'pointer',
              border: 'none', background: 'transparent',
              color: tab === t.id ? 'var(--blue-l)' : 'var(--text-2)',
              borderBottom: tab === t.id ? '2px solid var(--blue-l)' : '2px solid transparent',
              marginBottom: -1,
            }}
          >{t.label}</button>
        ))}
        {data.source_url && (
          <a href={data.source_url} target="_blank" rel="noopener noreferrer"
            style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--cyan)', textDecoration: 'none', padding: '0 4px' }}>
            <ExternalLink size={11} /> Source
          </a>
        )}
      </div>

      {tab === 'code' && (
        <pre className="code-block" style={{ maxHeight: 450, overflow: 'auto' }}>
          {data.implementation_code || '# No implementation code available'}
        </pre>
      )}

      {tab === 'yaml' && (
        <pre className="code-block" style={{ maxHeight: 450, overflow: 'auto' }}>
          {data.yaml_definition || '# No YAML definition available'}
        </pre>
      )}

      {tab === 'meta' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {[
            ['Check ID', data.check_id],
            ['Source Type', check.source_type],
            ['Source Vendor', data.source_vendor],
            ['Source Product', check.source_product],
            ['Source Version', check.source_version],
            ['Retrieved', check.source_retrieved],
            ['Normalization Confidence', check.normalization_confidence],
            ['Implementation Status', check.status],
            ['Collection Method', check.collection_method],
          ].map(([k, v]) => v ? (
            <div key={k as string} style={{ background: 'var(--navy-2)', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>{k as string}</div>
              <div style={{ fontSize: 13, color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>{v as string}</div>
            </div>
          ) : null)}
          {data.license_notes && (
            <div style={{ gridColumn: '1/-1', background: 'rgba(6,182,212,0.08)', border: '1px solid rgba(6,182,212,0.2)', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>License / Provenance Notes</div>
              <div style={{ fontSize: 12, color: 'var(--text)' }}>{data.license_notes}</div>
            </div>
          )}
          {data.logic_explanation && (
            <div style={{ gridColumn: '1/-1', background: 'var(--navy-2)', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>Logic Explanation</div>
              <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7 }}>{data.logic_explanation}</div>
            </div>
          )}
        </div>
      )}

      {tab === 'tests' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {(data.test_cases || []).map((tc: any, i: number) => (
            <div key={i} style={{ background: 'var(--navy-2)', borderRadius: 8, padding: '12px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Test Case {i + 1}</span>
                <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 999, background: tc.expected_pass ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)', color: tc.expected_pass ? 'var(--low)' : 'var(--crit)' }}>
                  Expected: {tc.expected_pass ? 'PASS' : 'FAIL'}
                </span>
              </div>
              <pre className="code-block" style={{ fontSize: 11 }}>{JSON.stringify(tc.input, null, 2)}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
