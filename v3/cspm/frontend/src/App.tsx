import React, { useState } from 'react'
import { Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, ShieldAlert, Database, BookOpen,
  Server, Scan, FileText, Settings, ChevronLeft, ChevronRight,
  Shield, Wifi
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import Assets from './pages/Assets'
import Checks from './pages/Checks'
import Connections from './pages/Connections'
import Scans from './pages/Scans'
import Reports from './pages/Reports'

const NAV = [
  { to: '/',            label: 'Dashboard',   icon: LayoutDashboard },
  { to: '/findings',    label: 'Findings',    icon: ShieldAlert },
  { to: '/assets',      label: 'Assets',      icon: Database },
  { to: '/checks',      label: 'Check Catalog', icon: BookOpen },
  { to: '/connections', label: 'Connections', icon: Wifi },
  { to: '/scans',       label: 'Scans',       icon: Scan },
  { to: '/reports',     label: 'Reports',     icon: FileText },
]

export default function App() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', width: '100%' }}>
      {/* Sidebar */}
      <aside style={{
        width: collapsed ? 56 : 220,
        minWidth: collapsed ? 56 : 220,
        background: 'var(--surface)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        transition: 'width 0.2s, min-width 0.2s',
        overflow: 'hidden',
      }}>
        {/* Logo */}
        <div style={{ padding: '16px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Shield size={24} color="var(--blue)" strokeWidth={2.5} style={{ flexShrink: 0 }} />
          {!collapsed && (
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 13, color: 'var(--white)', lineHeight: 1.2 }}>CloudGuard</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--blue-l)' }}>Pro CSPM</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 8px', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
              title={collapsed ? label : undefined}
            >
              <Icon size={16} style={{ flexShrink: 0 }} />
              {!collapsed && label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding: '12px 8px', borderTop: '1px solid var(--border)' }}>
          <button
            className="nav-link"
            onClick={() => setCollapsed(c => !c)}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? <ChevronRight size={16} /> : <><ChevronLeft size={16} /><span>Collapse</span></>}
          </button>
          {!collapsed && (
            <div style={{ padding: '8px 6px 0', fontSize: 11, color: 'var(--text-2)' }}>
              Aniza Corp v3.0.0
            </div>
          )}
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflow: 'auto', background: 'var(--navy)' }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/findings/*" element={<Findings />} />
          <Route path="/assets/*" element={<Assets />} />
          <Route path="/checks/*" element={<Checks />} />
          <Route path="/connections/*" element={<Connections />} />
          <Route path="/scans/*" element={<Scans />} />
          <Route path="/reports/*" element={<Reports />} />
        </Routes>
      </main>
    </div>
  )
}
