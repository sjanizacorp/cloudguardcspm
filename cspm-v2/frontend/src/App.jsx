import { useState, useEffect, useCallback, useRef } from "react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, PieChart, Pie, ResponsiveContainer, CartesianGrid } from "recharts";

const API = "http://localhost:8000/api";
const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280" };
const CLOUD_COLOR = { aws: "#FF9900", azure: "#0078D4", gcp: "#4285F4" };
const CLOUD_ICON = { aws: "☁", azure: "⬡", gcp: "◈" };
const STATUS_COLOR = { active: "#ef4444", suppressed: "#6b7280", accepted: "#8b5cf6", resolved: "#10b981" };

// ── API helpers ───────────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

// ── Components ────────────────────────────────────────────────────────────────
function Badge({ value, type = "severity" }) {
  const colors = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    passed: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    failed: "bg-red-500/20 text-red-400 border-red-500/30",
    active: "bg-red-500/20 text-red-400 border-red-500/30",
    suppressed: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    accepted: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    resolved: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold uppercase tracking-wide border ${colors[value] || colors.info}`}>
      {value}
    </span>
  );
}

function ScoreRing({ score }) {
  const r = 52, circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? "#10b981" : score >= 60 ? "#eab308" : score >= 40 ? "#f97316" : "#ef4444";
  const label = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";
  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={130} height={130} className="-rotate-90">
        <circle cx={65} cy={65} r={r} fill="none" stroke="#1e293b" strokeWidth={10} />
        <circle cx={65} cy={65} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 1.2s ease" }} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-black" style={{ color }}>{Math.round(score)}</span>
        <span className="text-xs font-semibold" style={{ color }}>{label}</span>
      </div>
    </div>
  );
}

function StatCard({ label, value, sub, accent, onClick }) {
  return (
    <div onClick={onClick} className={`bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 flex flex-col gap-1 ${onClick ? "cursor-pointer hover:border-slate-600 transition-colors" : ""}`}>
      <span className="text-xs text-slate-400 font-mono uppercase tracking-widest">{label}</span>
      <span className="text-3xl font-black" style={{ color: accent || "#f8fafc" }}>{value ?? "—"}</span>
      {sub && <span className="text-xs text-slate-500">{sub}</span>}
    </div>
  );
}

function Card({ title, children, action }) {
  return (
    <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-mono text-slate-400 uppercase tracking-widest">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}

// ── Scan Modal ────────────────────────────────────────────────────────────────
function ScanModal({ onDone, onClose }) {
  const [form, setForm] = useState({ aws_key: "", aws_secret: "", aws_token: "", az_tenant: "", az_client: "", az_secret: "", az_sub: "", gcp_project: "", gcp_creds: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));
  const pollRef = useRef(null);

  const submit = async () => {
    setBusy(true); setMsg("Starting scan...");
    const body = {};
    if (form.aws_key && form.aws_secret) body.aws = { access_key: form.aws_key, secret_key: form.aws_secret, ...(form.aws_token && { session_token: form.aws_token }) };
    if (form.az_tenant) body.azure = { tenant_id: form.az_tenant, client_id: form.az_client, client_secret: form.az_secret, subscription_id: form.az_sub };
    if (form.gcp_project) { body.gcp = { project_id: form.gcp_project }; if (form.gcp_creds) try { body.gcp.credentials_json = JSON.parse(form.gcp_creds); } catch {} }
    if (!Object.keys(body).length) { setMsg("Configure at least one provider"); setBusy(false); return; }
    try {
      await api("/scan/start", { method: "POST", body: JSON.stringify(body) });
      setMsg("Scan running...");
      pollRef.current = setInterval(async () => {
        const s = await api("/scan/status/latest");
        setMsg(`${s.status === "running" ? "⟳" : "✅"} ${s.assets_count || 0} assets · ${s.findings_count || 0} findings`);
        if (s.status === "completed" || s.status === "failed") {
          clearInterval(pollRef.current);
          setBusy(false);
          if (s.status === "completed") { setTimeout(() => { onDone(); onClose(); }, 1200); }
        }
      }, 2000);
    } catch (e) { setMsg(`❌ ${e.message}`); setBusy(false); }
  };

  useEffect(() => () => pollRef.current && clearInterval(pollRef.current), []);

  const F = ({ label, k, type = "text", placeholder = "" }) => (
    <div className="flex flex-col gap-1">
      <label className="text-xs text-slate-400 font-mono">{label}</label>
      <input type={type} value={form[k]} onChange={set(k)} placeholder={placeholder}
        className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors" />
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-5">
          <h2 className="text-xl font-black text-white">New Scan</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-2xl">×</button>
        </div>
        <div className="space-y-4">
          <div className="bg-slate-900/50 rounded-xl p-4 border border-amber-500/20">
            <h3 className="text-sm font-bold text-amber-400 mb-3">☁ Amazon Web Services</h3>
            <div className="grid grid-cols-2 gap-3">
              <F label="Access Key ID" k="aws_key" placeholder="AKIA..." />
              <F label="Secret Access Key" k="aws_secret" type="password" placeholder="wJalrX..." />
              <div className="col-span-2"><F label="Session Token (optional)" k="aws_token" /></div>
            </div>
          </div>
          <div className="bg-slate-900/50 rounded-xl p-4 border border-blue-500/20">
            <h3 className="text-sm font-bold text-blue-400 mb-3">⬡ Microsoft Azure</h3>
            <div className="grid grid-cols-2 gap-3">
              <F label="Tenant ID" k="az_tenant" placeholder="xxxxxxxx-xxxx..." />
              <F label="Client ID" k="az_client" placeholder="xxxxxxxx-xxxx..." />
              <F label="Client Secret" k="az_secret" type="password" />
              <F label="Subscription ID" k="az_sub" placeholder="xxxxxxxx-xxxx..." />
            </div>
          </div>
          <div className="bg-slate-900/50 rounded-xl p-4 border border-cyan-500/20">
            <h3 className="text-sm font-bold text-cyan-400 mb-3">◈ Google Cloud Platform</h3>
            <div className="space-y-3">
              <F label="Project ID" k="gcp_project" placeholder="my-project-123" />
              <div className="flex flex-col gap-1">
                <label className="text-xs text-slate-400 font-mono">Service Account JSON (optional)</label>
                <textarea rows={3} value={form.gcp_creds} onChange={set("gcp_creds")} placeholder={'{"type": "service_account", ...}'}
                  className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors resize-none" />
              </div>
            </div>
          </div>
        </div>
        {msg && <div className="mt-4 p-3 bg-slate-900 rounded-lg border border-slate-700 text-sm text-slate-300 font-mono">{msg}</div>}
        <div className="flex gap-3 mt-5">
          <button onClick={onClose} className="flex-1 px-4 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-xl font-semibold transition-colors">Cancel</button>
          <button onClick={submit} disabled={busy} className="flex-1 px-4 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-600 disabled:cursor-not-allowed text-white rounded-xl font-bold transition-colors flex items-center justify-center gap-2">
            {busy ? <><span className="animate-spin inline-block">⟳</span> Running...</> : "▶ Start Scan"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Finding Detail Modal ──────────────────────────────────────────────────────
function FindingModal({ finding, onClose, onStatusChange }) {
  const [reason, setReason] = useState("");
  const [action, setAction] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (type) => {
    setBusy(true);
    try {
      await api(`/findings/${finding.id}/${type}`, { method: "POST", body: JSON.stringify({ reason: reason || `Marked as ${type}`, suppressed_by: "user" }) });
      onStatusChange();
      onClose();
    } catch (e) { alert(e.message); }
    setBusy(false);
  };

  const reopen = async () => {
    setBusy(true);
    try { await api(`/findings/${finding.id}/reopen`, { method: "POST" }); onStatusChange(); onClose(); } catch (e) { alert(e.message); }
    setBusy(false);
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 w-full max-w-lg" onClick={e => e.stopPropagation()}>
        <div className="flex justify-between items-start mb-4">
          <div className="flex flex-col gap-2">
            <Badge value={finding.severity} />
            <h3 className="text-lg font-bold text-white">{finding.title}</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-2xl ml-4 flex-shrink-0">×</button>
        </div>
        <div className="space-y-4 text-sm">
          <div>
            <div className="text-xs text-slate-500 font-mono mb-1">RESOURCE</div>
            <div className="font-mono text-slate-300">{finding.resource_id}</div>
            <div className="text-slate-500 text-xs mt-0.5">{CLOUD_ICON[finding.cloud_provider]} {finding.cloud_provider?.toUpperCase()} · {finding.resource_type} · {finding.region}</div>
          </div>
          <div><div className="text-xs text-slate-500 font-mono mb-1">DESCRIPTION</div><p className="text-slate-300">{finding.description}</p></div>
          <div className="bg-emerald-900/20 border border-emerald-700/30 rounded-xl p-4">
            <div className="text-xs text-emerald-400 font-mono mb-1">🔧 REMEDIATION</div>
            <p className="text-slate-300">{finding.remediation}</p>
          </div>
          {finding.suppressed_reason && (
            <div className="bg-slate-900/50 border border-slate-700 rounded-xl p-3">
              <div className="text-xs text-slate-500 font-mono mb-1">SUPPRESSION REASON</div>
              <p className="text-slate-400">{finding.suppressed_reason}</p>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            {finding.cis_controls?.map(c => <span key={c} className="px-2 py-1 bg-slate-700 rounded text-xs font-mono text-slate-300">{c}</span>)}
            {finding.nist_controls?.map(c => <span key={c} className="px-2 py-1 bg-slate-700 rounded text-xs font-mono text-slate-300">NIST {c}</span>)}
          </div>

          {/* Actions */}
          {finding.status === "active" && (
            <div className="border-t border-slate-700 pt-4">
              <div className="text-xs text-slate-500 font-mono mb-2">MANAGE FINDING</div>
              <textarea value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason (optional)..." rows={2}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 resize-none mb-3" />
              <div className="flex gap-2">
                <button onClick={() => submit("suppress")} disabled={busy} className="flex-1 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-xs font-semibold transition-colors">
                  Suppress
                </button>
                <button onClick={() => submit("accept")} disabled={busy} className="flex-1 px-3 py-2 bg-purple-800/50 hover:bg-purple-700/50 text-purple-300 rounded-lg text-xs font-semibold transition-colors">
                  Accept Risk
                </button>
              </div>
            </div>
          )}
          {(finding.status === "suppressed" || finding.status === "accepted") && (
            <div className="border-t border-slate-700 pt-4">
              <button onClick={reopen} disabled={busy} className="w-full px-3 py-2 bg-cyan-800/30 hover:bg-cyan-700/30 text-cyan-300 rounded-lg text-xs font-semibold transition-colors">
                ↩ Reopen Finding
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Schedule Modal ────────────────────────────────────────────────────────────
function ScheduleModal({ onDone, onClose }) {
  const [form, setForm] = useState({ name: "", cron: "0 */6 * * *", aws_key: "", aws_secret: "", gcp_project: "" });
  const [busy, setBusy] = useState(false);
  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

  const PRESETS = [
    { label: "Every 6 hours", cron: "0 */6 * * *" },
    { label: "Daily at midnight", cron: "0 0 * * *" },
    { label: "Weekly (Mon 9am)", cron: "0 9 * * 1" },
    { label: "Hourly", cron: "0 * * * *" },
  ];

  const submit = async () => {
    setBusy(true);
    const cloud_config = {};
    if (form.aws_key && form.aws_secret) cloud_config.aws = { access_key: form.aws_key, secret_key: form.aws_secret };
    if (form.gcp_project) cloud_config.gcp = { project_id: form.gcp_project };
    if (!Object.keys(cloud_config).length) { alert("Configure at least one cloud provider"); setBusy(false); return; }
    try {
      await api("/schedules", { method: "POST", body: JSON.stringify({ name: form.name || "Scheduled Scan", cron_expression: form.cron, cloud_config }) });
      onDone(); onClose();
    } catch (e) { alert(e.message); setBusy(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 w-full max-w-lg">
        <div className="flex justify-between items-center mb-5">
          <h2 className="text-lg font-black text-white">Schedule Scan</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-2xl">×</button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-slate-400 font-mono block mb-1">NAME</label>
            <input value={form.name} onChange={set("name")} placeholder="Production scan"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500" />
          </div>
          <div>
            <label className="text-xs text-slate-400 font-mono block mb-1">SCHEDULE</label>
            <div className="flex gap-2 mb-2">
              {PRESETS.map(p => (
                <button key={p.cron} onClick={() => setForm(f => ({ ...f, cron: p.cron }))}
                  className={`px-2 py-1 rounded text-xs font-mono transition-colors ${form.cron === p.cron ? "bg-cyan-600 text-white" : "bg-slate-700 text-slate-300 hover:bg-slate-600"}`}>
                  {p.label}
                </button>
              ))}
            </div>
            <input value={form.cron} onChange={set("cron")} placeholder="0 */6 * * *"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-500" />
          </div>
          <div className="border-t border-slate-700 pt-4">
            <div className="text-xs text-slate-400 font-mono mb-3">CLOUD CREDENTIALS</div>
            <div className="space-y-2">
              <input value={form.aws_key} onChange={set("aws_key")} placeholder="AWS Access Key ID"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500" />
              <input type="password" value={form.aws_secret} onChange={set("aws_secret")} placeholder="AWS Secret Access Key"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500" />
              <input value={form.gcp_project} onChange={set("gcp_project")} placeholder="GCP Project ID"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500" />
            </div>
          </div>
        </div>
        <div className="flex gap-3 mt-5">
          <button onClick={onClose} className="flex-1 px-4 py-3 bg-slate-700 text-white rounded-xl font-semibold">Cancel</button>
          <button onClick={submit} disabled={busy} className="flex-1 px-4 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-600 text-white rounded-xl font-bold">
            {busy ? "Saving..." : "Create Schedule"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [nav, setNav] = useState("dashboard");
  const [summary, setSummary] = useState(null);
  const [assets, setAssets] = useState({ total: 0, assets: [] });
  const [findings, setFindings] = useState({ total: 0, findings: [] });
  const [compliance, setCompliance] = useState(null);
  const [schedules, setSchedules] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [showScan, setShowScan] = useState(false);
  const [showSchedule, setShowSchedule] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [loading, setLoading] = useState(false);
  const [findingFilter, setFindingFilter] = useState({ severity: "", cloud: "", status: "active" });
  const [assetSearch, setAssetSearch] = useState("");
  const [complianceFilter, setComplianceFilter] = useState({ framework: "", status: "" });

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [s, a, f, c, sc, h] = await Promise.all([
        api("/dashboard/summary"),
        api("/assets?limit=500"),
        api("/findings?limit=500&status=active"),
        api("/compliance"),
        api("/schedules"),
        api("/scan/history?limit=15"),
      ]);
      setSummary(s); setAssets(a); setFindings(f);
      setCompliance(c); setSchedules(sc); setScanHistory(h);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-poll if scan is running
  useEffect(() => {
    if (summary?.last_scan_status === "running") {
      const t = setTimeout(refresh, 3000);
      return () => clearTimeout(t);
    }
  }, [summary, refresh]);

  const filteredFindings = useCallback(() => {
    return findings.findings.filter(f => {
      if (findingFilter.severity && f.severity !== findingFilter.severity) return false;
      if (findingFilter.cloud && f.cloud_provider !== findingFilter.cloud) return false;
      return true;
    });
  }, [findings, findingFilter]);

  const filteredAssets = useCallback(() => {
    if (!assetSearch) return assets.assets;
    const s = assetSearch.toLowerCase();
    return assets.assets.filter(a => a.name?.toLowerCase().includes(s) || a.resource_type?.toLowerCase().includes(s) || a.resource_id?.toLowerCase().includes(s));
  }, [assets, assetSearch]);

  const filteredCompliance = useCallback(() => {
    if (!compliance?.controls) return [];
    return compliance.controls.filter(c => {
      if (complianceFilter.framework && c.framework !== complianceFilter.framework) return false;
      if (complianceFilter.status && c.status !== complianceFilter.status) return false;
      return true;
    });
  }, [compliance, complianceFilter]);

  const score = summary?.secure_score?.score ?? 0;
  const sevData = ["critical", "high", "medium", "low"].map(s => ({ name: s[0].toUpperCase() + s.slice(1), value: summary?.findings_by_severity?.[s] || 0, color: SEV_COLOR[s] })).filter(x => x.value > 0);
  const cloudData = Object.entries(summary?.assets_by_cloud || {}).map(([k, v]) => ({ name: k.toUpperCase(), value: v, color: CLOUD_COLOR[k] }));
  const trend = summary?.score_trend || [];

  const NAV = [
    { id: "dashboard", icon: "◈", label: "Dashboard" },
    { id: "assets", icon: "⬡", label: "Assets" },
    { id: "findings", icon: "⚠", label: "Findings", badge: findings.findings.length },
    { id: "compliance", icon: "✓", label: "Compliance" },
    { id: "schedules", icon: "◷", label: "Schedules" },
    { id: "history", icon: "⟳", label: "History" },
  ];

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex" style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
      <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&family=Space+Grotesk:wght@600;700;800;900&display=swap" rel="stylesheet" />

      {/* Sidebar */}
      <aside className="w-52 bg-slate-950 border-r border-slate-800 flex flex-col py-6 px-3 fixed h-full z-10">
        <div className="mb-8 px-2">
          <div className="text-lg font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            <span className="text-cyan-400">Cloud</span><span className="text-white">Guard</span>
          </div>
          <div className="text-xs text-slate-600 mt-0.5">v2.0 · CSPM</div>
        </div>

        <nav className="flex flex-col gap-0.5 flex-1">
          {NAV.map(item => (
            <button key={item.id} onClick={() => setNav(item.id)}
              className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-semibold transition-all text-left ${nav === item.id ? "bg-cyan-600/20 text-cyan-400 border border-cyan-500/30" : "text-slate-400 hover:text-white hover:bg-slate-800/80"}`}>
              <span className="text-base w-4 text-center">{item.icon}</span>
              <span>{item.label}</span>
              {item.badge > 0 && <span className="ml-auto text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded font-mono">{item.badge}</span>}
            </button>
          ))}
        </nav>

        <div className="space-y-2 mt-4">
          <button onClick={() => setShowSchedule(true)} className="w-full px-3 py-2 bg-slate-700/80 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 justify-center">
            ◷ Schedule
          </button>
          <button onClick={() => setShowScan(true)} className="w-full px-3 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl font-bold text-sm transition-colors flex items-center justify-center gap-2">
            {loading ? <span className="animate-spin">⟳</span> : "▶"} Scan Now
          </button>
        </div>

        {summary?.last_scan && (
          <div className="mt-3 text-xs text-slate-600 text-center px-2">
            Last scan: {new Date(summary.last_scan).toLocaleDateString()}
            {summary.last_scan_status === "running" && <span className="text-cyan-400 ml-1 animate-pulse">● running</span>}
          </div>
        )}
      </aside>

      {/* Main content */}
      <main className="ml-52 flex-1 p-6 min-h-screen">

        {/* ── DASHBOARD ──────────────────────────────────────────────────── */}
        {nav === "dashboard" && (
          <div className="space-y-5 max-w-7xl">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Security Posture</h1>
                <p className="text-xs text-slate-500 mt-0.5 font-mono">{summary?.providers_scanned?.join(" · ").toUpperCase() || "No scans yet"}</p>
              </div>
            </div>

            {!summary?.total_assets ? (
              <div className="border border-slate-700/50 border-dashed rounded-2xl p-16 text-center">
                <div className="text-5xl mb-4">🔍</div>
                <h2 className="text-xl font-bold text-white mb-2">No data yet</h2>
                <p className="text-slate-400 text-sm mb-6">Run your first scan to start discovering assets and security issues.</p>
                <button onClick={() => setShowScan(true)} className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl font-bold transition-colors">Run First Scan</button>
              </div>
            ) : (<>
              {/* Top row */}
              <div className="grid grid-cols-6 gap-4">
                <div className="col-span-1 bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 flex flex-col items-center justify-center">
                  <div className="text-xs text-slate-400 font-mono uppercase tracking-widest mb-2">Score</div>
                  <ScoreRing score={score} />
                  <div className="text-xs text-slate-500 mt-2 text-center">{summary?.secure_score?.critical} critical issues</div>
                </div>
                <div className="col-span-5 grid grid-cols-4 gap-4">
                  <StatCard label="Total Assets" value={summary?.total_assets} sub={`${Object.keys(summary?.assets_by_cloud || {}).length} clouds`} />
                  <StatCard label="Active Findings" value={summary?.total_findings} accent="#ef4444" sub={`${summary?.suppressed_findings || 0} suppressed`} onClick={() => setNav("findings")} />
                  <StatCard label="Critical" value={summary?.findings_by_severity?.critical || 0} accent={SEV_COLOR.critical} sub="immediate action needed" onClick={() => { setFindingFilter(f => ({ ...f, severity: "critical" })); setNav("findings"); }} />
                  <StatCard label="Public Resources" value={summary?.public_resources} accent="#eab308" sub="internet exposed" />
                </div>
              </div>

              {/* Charts */}
              <div className="grid grid-cols-3 gap-4">
                <Card title="Findings by Severity">
                  <ResponsiveContainer width="100%" height={160}>
                    <PieChart><Pie data={sevData} dataKey="value" cx="50%" cy="50%" outerRadius={65} labelLine={false}
                      label={({ name, value }) => `${name[0]}: ${value}`} fontSize={11}>
                      {sevData.map((d, i) => <Cell key={i} fill={d.color} />)}
                    </Pie><Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }} /></PieChart>
                  </ResponsiveContainer>
                </Card>
                <Card title="Assets by Cloud">
                  <ResponsiveContainer width="100%" height={160}>
                    <BarChart data={cloudData} barSize={40}>
                      <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }} />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>{cloudData.map((d, i) => <Cell key={i} fill={d.color} />)}</Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </Card>
                <Card title="Compliance">
                  {Object.entries(summary?.compliance_summary || {}).map(([fw, data]) => (
                    <div key={fw} className="mb-3">
                      <div className="flex justify-between text-xs mb-1">
                        <span className="font-mono text-slate-400">{fw}</span>
                        <span className="text-white font-bold">{data.percentage}%</span>
                      </div>
                      <div className="w-full bg-slate-700 rounded-full h-1.5">
                        <div className="h-1.5 rounded-full transition-all" style={{ width: `${data.percentage}%`, background: data.percentage >= 70 ? "#10b981" : data.percentage >= 50 ? "#eab308" : "#ef4444" }} />
                      </div>
                      <div className="flex gap-3 text-xs mt-1">
                        <span className="text-emerald-400">✓ {data.passed}</span>
                        <span className="text-red-400">✗ {data.failed}</span>
                      </div>
                    </div>
                  ))}
                </Card>
              </div>

              {/* Score trend */}
              {trend.length > 1 && (
                <Card title="Secure Score Trend">
                  <ResponsiveContainer width="100%" height={120}>
                    <AreaChart data={trend}>
                      <defs>
                        <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="date" tick={{ fill: "#94a3b8", fontSize: 10 }} tickFormatter={d => new Date(d).toLocaleDateString()} axisLine={false} tickLine={false} />
                      <YAxis domain={[0, 100]} tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
                        formatter={(v) => [v?.toFixed(1), "Score"]} labelFormatter={d => new Date(d).toLocaleString()} />
                      <Area type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2} fill="url(#scoreGrad)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </Card>
              )}

              {/* Top findings */}
              {summary?.top_findings?.length > 0 && (
                <Card title="Top Priority Findings">
                  <div className="divide-y divide-slate-800">
                    {summary.top_findings.map(f => (
                      <div key={f.id} onClick={() => setSelectedFinding(f)} className="flex items-center gap-3 py-2.5 hover:bg-slate-800/40 rounded-lg px-2 cursor-pointer transition-colors">
                        <Badge value={f.severity} />
                        <span className="flex-1 text-sm text-slate-200 truncate">{f.title}</span>
                        <span className="text-xs text-slate-500 font-mono">{CLOUD_ICON[f.cloud_provider]} {f.resource_type}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </>)}
          </div>
        )}

        {/* ── ASSETS ─────────────────────────────────────────────────────── */}
        {nav === "assets" && (
          <div className="space-y-4 max-w-7xl">
            <div className="flex items-center justify-between">
              <h1 className="text-2xl font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Asset Inventory</h1>
              <span className="text-sm text-slate-400 font-mono">{filteredAssets().length} / {assets.total} resources</span>
            </div>
            <input value={assetSearch} onChange={e => setAssetSearch(e.target.value)} placeholder="Search by name, type, ID..."
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors" />
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-slate-700">
                  {["Cloud", "Type", "Name / ID", "Region", "Account", "Exposure"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-mono text-slate-400 uppercase tracking-widest">{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {filteredAssets().slice(0, 250).map(a => (
                    <tr key={a.id} className="border-b border-slate-800/80 hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-2.5"><span className="text-sm font-mono" style={{ color: CLOUD_COLOR[a.cloud_provider] }}>{CLOUD_ICON[a.cloud_provider]} {a.cloud_provider?.toUpperCase()}</span></td>
                      <td className="px-4 py-2.5 text-xs text-slate-400 font-mono">{a.resource_type}</td>
                      <td className="px-4 py-2.5 text-slate-200 max-w-xs"><div className="truncate">{a.name}</div><div className="text-xs text-slate-500 font-mono truncate">{a.resource_id}</div></td>
                      <td className="px-4 py-2.5 text-xs text-slate-500 font-mono">{a.region}</td>
                      <td className="px-4 py-2.5 text-xs text-slate-500 font-mono">{a.account_id?.slice(0, 12)}</td>
                      <td className="px-4 py-2.5">{a.is_public ? <Badge value="critical" /> : <span className="text-xs text-slate-600 font-mono">private</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredAssets().length === 0 && <div className="text-center py-12 text-slate-500">No assets found. Run a scan first.</div>}
            </div>
          </div>
        )}

        {/* ── FINDINGS ───────────────────────────────────────────────────── */}
        {nav === "findings" && (
          <div className="space-y-4 max-w-7xl">
            <div className="flex items-center justify-between">
              <h1 className="text-2xl font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Findings</h1>
              <span className="text-sm text-slate-400 font-mono">{filteredFindings().length} shown</span>
            </div>

            {/* Filters */}
            <div className="flex flex-wrap gap-2">
              <div className="flex gap-1">
                {["", "critical", "high", "medium", "low"].map(s => (
                  <button key={s} onClick={() => setFindingFilter(f => ({ ...f, severity: s }))}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold uppercase transition-colors ${findingFilter.severity === s ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}>
                    {s || "All"}
                  </button>
                ))}
              </div>
              <div className="flex gap-1 ml-auto">
                {["active", "suppressed", "accepted"].map(s => (
                  <button key={s} onClick={() => { setFindingFilter(f => ({ ...f, status: s })); }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold uppercase transition-colors ${findingFilter.status === s ? "bg-slate-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}>
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl divide-y divide-slate-800">
              {filteredFindings().length === 0
                ? <div className="text-center py-12 text-slate-500">No findings matching current filters.</div>
                : filteredFindings().map(f => (
                    <div key={f.id} onClick={() => setSelectedFinding(f)} className="flex items-center gap-3 p-3 hover:bg-slate-800/60 cursor-pointer transition-colors">
                      <Badge value={f.severity} />
                      {f.status !== "active" && <Badge value={f.status} />}
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-semibold text-slate-200 truncate">{f.title}</div>
                        <div className="text-xs text-slate-400 font-mono mt-0.5">{CLOUD_ICON[f.cloud_provider]} {f.cloud_provider?.toUpperCase()} · {f.resource_type} · <span className="text-slate-500">{f.resource_id}</span></div>
                      </div>
                      {f.cis_controls?.[0] && <span className="text-xs text-slate-600 font-mono hidden lg:block">{f.cis_controls[0]}</span>}
                      <span className="text-slate-600">›</span>
                    </div>
                  ))
              }
            </div>
          </div>
        )}

        {/* ── COMPLIANCE ─────────────────────────────────────────────────── */}
        {nav === "compliance" && (
          <div className="space-y-4 max-w-7xl">
            <h1 className="text-2xl font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Compliance</h1>
            {compliance && (
              <>
                <div className="grid grid-cols-3 gap-4">
                  <StatCard label="Total Controls" value={compliance.total} />
                  <StatCard label="Passing" value={compliance.passed} accent="#10b981" />
                  <StatCard label="Failing" value={compliance.failed} accent="#ef4444" />
                </div>
                <div className="flex gap-2">
                  {["", "CIS", "NIST"].map(fw => (
                    <button key={fw} onClick={() => setComplianceFilter(f => ({ ...f, framework: fw }))}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold uppercase transition-colors ${complianceFilter.framework === fw ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}>
                      {fw || "All Frameworks"}
                    </button>
                  ))}
                  {["", "passed", "failed"].map(st => (
                    <button key={st} onClick={() => setComplianceFilter(f => ({ ...f, status: st }))}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold uppercase transition-colors ml-1 ${complianceFilter.status === st ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}>
                      {st || "All Status"}
                    </button>
                  ))}
                </div>
                <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b border-slate-700">
                      {["Framework", "Control ID", "Title", "Cloud", "Status"].map(h => (
                        <th key={h} className="text-left px-4 py-3 text-xs font-mono text-slate-400 uppercase tracking-widest">{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {filteredCompliance().map(c => (
                        <tr key={c.id} className="border-b border-slate-800/80 hover:bg-slate-800/40 transition-colors">
                          <td className="px-4 py-2.5"><span className="text-xs font-mono font-bold text-cyan-400">{c.framework}</span></td>
                          <td className="px-4 py-2.5 text-xs font-mono text-slate-400">{c.control_id}</td>
                          <td className="px-4 py-2.5 text-xs text-slate-200 max-w-sm">{c.control_title}</td>
                          <td className="px-4 py-2.5 text-xs font-mono" style={{ color: CLOUD_COLOR[c.cloud_provider] || "#94a3b8" }}>
                            {c.cloud_provider === "multi" ? "ALL" : c.cloud_provider?.toUpperCase()}
                          </td>
                          <td className="px-4 py-2.5"><Badge value={c.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredCompliance().length === 0 && <div className="text-center py-12 text-slate-500">No compliance data. Run a scan first.</div>}
                </div>
              </>
            )}
          </div>
        )}

        {/* ── SCHEDULES ──────────────────────────────────────────────────── */}
        {nav === "schedules" && (
          <div className="space-y-4 max-w-4xl">
            <div className="flex items-center justify-between">
              <h1 className="text-2xl font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Scheduled Scans</h1>
              <button onClick={() => setShowSchedule(true)} className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl font-bold text-sm transition-colors">+ New Schedule</button>
            </div>
            {schedules.length === 0
              ? <div className="border border-slate-700/50 border-dashed rounded-2xl p-12 text-center">
                  <div className="text-4xl mb-3">◷</div>
                  <p className="text-slate-400 text-sm mb-4">No scheduled scans yet. Set one up to automatically monitor your cloud security posture.</p>
                  <button onClick={() => setShowSchedule(true)} className="px-4 py-2 bg-cyan-600 text-white rounded-xl font-bold text-sm">Create Schedule</button>
                </div>
              : <div className="space-y-3">
                  {schedules.map(s => (
                    <div key={s.id} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 flex items-center gap-4">
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${s.enabled ? "bg-emerald-400" : "bg-slate-600"}`} />
                      <div className="flex-1">
                        <div className="font-semibold text-slate-200">{s.name}</div>
                        <div className="text-xs text-slate-500 font-mono mt-0.5">
                          {s.cron_expression} · {s.run_count} runs
                          {s.last_run && ` · last: ${new Date(s.last_run).toLocaleString()}`}
                          {s.next_run && ` · next: ${new Date(s.next_run).toLocaleString()}`}
                        </div>
                      </div>
                      <button onClick={async () => { await api(`/schedules/${s.id}/toggle`, { method: "PATCH" }); refresh(); }}
                        className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${s.enabled ? "bg-slate-700 text-slate-300 hover:bg-slate-600" : "bg-emerald-700/30 text-emerald-300 hover:bg-emerald-700/50"}`}>
                        {s.enabled ? "Pause" : "Resume"}
                      </button>
                      <button onClick={async () => { if (confirm("Delete this schedule?")) { await api(`/schedules/${s.id}`, { method: "DELETE" }); refresh(); } }}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-900/30 text-red-400 hover:bg-red-900/50 transition-colors">
                        Delete
                      </button>
                    </div>
                  ))}
                </div>
            }
          </div>
        )}

        {/* ── HISTORY ────────────────────────────────────────────────────── */}
        {nav === "history" && (
          <div className="space-y-4 max-w-5xl">
            <h1 className="text-2xl font-black" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>Scan History</h1>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-slate-700">
                  {["Started", "Status", "Clouds", "Assets", "Findings", "Critical", "Score", "Trigger"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-mono text-slate-400 uppercase tracking-widest">{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {scanHistory.map(s => (
                    <tr key={s.scan_id} className="border-b border-slate-800/80 hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3 text-xs text-slate-400 font-mono">{s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</td>
                      <td className="px-4 py-3"><Badge value={s.status === "completed" ? "passed" : s.status === "running" ? "info" : "failed"} /></td>
                      <td className="px-4 py-3 text-xs font-mono">{(s.cloud_providers || []).map(p => <span key={p} style={{ color: CLOUD_COLOR[p] }}>{CLOUD_ICON[p]} </span>)}</td>
                      <td className="px-4 py-3 text-slate-300 font-mono">{s.assets_discovered || 0}</td>
                      <td className="px-4 py-3 text-slate-300 font-mono">{s.findings_count || 0}</td>
                      <td className="px-4 py-3"><span className="text-red-400 font-mono font-bold">{s.critical_count || 0}</span></td>
                      <td className="px-4 py-3">
                        {s.secure_score != null && (
                          <span className="font-mono font-bold" style={{ color: s.secure_score >= 80 ? "#10b981" : s.secure_score >= 60 ? "#eab308" : "#ef4444" }}>
                            {s.secure_score.toFixed(1)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3"><span className={`text-xs font-mono px-2 py-0.5 rounded ${s.triggered_by === "scheduled" ? "bg-purple-900/30 text-purple-400" : "bg-slate-700 text-slate-400"}`}>{s.triggered_by}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {scanHistory.length === 0 && <div className="text-center py-12 text-slate-500">No scan history yet.</div>}
            </div>
          </div>
        )}
      </main>

      {/* Modals */}
      {showScan && <ScanModal onDone={refresh} onClose={() => setShowScan(false)} />}
      {showSchedule && <ScheduleModal onDone={refresh} onClose={() => setShowSchedule(false)} />}
      {selectedFinding && <FindingModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} onStatusChange={refresh} />}
    </div>
  );
}
