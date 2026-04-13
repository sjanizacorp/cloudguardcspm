const BASE = '/api/v1'

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    const err = await res.text()
    throw new Error(`API ${res.status}: ${err}`)
  }
  return res.json()
}

export const api = {
  // Dashboard
  stats: () => request<any>('/dashboard/stats'),

  // Findings
  findings: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && q.set(k, String(v)))
    return request<any>(`/findings?${q}`)
  },
  finding: (id: string) => request<any>(`/findings/${id}`),
  suppressFinding: (id: string, body: any) => request<any>(`/findings/${id}/suppress`, { method: 'POST', body: JSON.stringify(body) }),

  // Assets
  assets: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && q.set(k, String(v)))
    return request<any>(`/assets?${q}`)
  },
  asset: (id: string) => request<any>(`/assets/${id}`),
  assetFindings: (id: string) => request<any>(`/assets/${id}/findings`),

  // Checks
  checks: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && q.set(k, String(v)))
    return request<any>(`/checks?${q}`)
  },
  checkFamilies: () => request<any[]>('/checks/families'),
  check: (id: string) => request<any>(`/checks/${id}`),
  checkCode: (id: string) => request<any>(`/checks/${id}/code`),

  // Connections
  connections: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && q.set(k, String(v)))
    return request<any>(`/connections?${q}`)
  },
  createConnection: (body: any) => request<any>('/connections', { method: 'POST', body: JSON.stringify(body) }),
  deleteConnection: (id: string) => request<any>(`/connections/${id}`, { method: 'DELETE' }),

  // Scans
  startScan: (body: any) => request<any>('/scans', { method: 'POST', body: JSON.stringify(body) }),
  scans: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && q.set(k, String(v)))
    return request<any>(`/scans?${q}`)
  },
  scan: (id: string) => request<any>(`/scans/${id}`),

  // Reports
  reports: () => request<any[]>('/reports'),
  createReport: (body: any) => request<any>('/reports', { method: 'POST', body: JSON.stringify(body) }),
  downloadReport: (id: string) => `${BASE}/reports/${id}/download`,

  // Health
  health: () => request<any>('/health/ready'),
}

export default api
