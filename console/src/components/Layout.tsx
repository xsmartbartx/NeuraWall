import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import type { Dashboard } from "../lib/api";
import { useApi, useAuth, useTheme } from "../lib/hooks";

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="var(--bg-raised)" stroke="var(--border-strong)" />
      <path d="M6 9h20M6 16h20M6 23h20" stroke="var(--border-strong)" strokeWidth="2" />
      <path d="M11 9v7M21 16v7M16 23v-7" stroke="var(--accent)" strokeWidth="2.4" strokeLinecap="round" />
      <circle cx="16" cy="16" r="2.6" fill="var(--accent)" />
    </svg>
  );
}

export function Layout() {
  const { me, can, logout } = useAuth();
  const [theme, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  const { data: dash } = useApi<Dashboard>("/dashboard?hours=24", { poll: 15000 });
  const openAlerts = dash ? Object.values(dash.open_alerts).reduce((a, b) => a + b, 0) : 0;
  const critical = (dash?.open_alerts.critical ?? 0) + (dash?.open_alerts.high ?? 0);

  const link = (to: string, label: string, count?: number, hot?: boolean) => (
    <NavLink to={to} end={to === "/"} onClick={() => setOpen(false)}>
      {label}
      {count ? <span className={`count ${hot ? "hot" : ""}`}>{count}</span> : null}
    </NavLink>
  );

  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand"><Logo /><div>NeuraWall<small>AI Firewall</small></div></div>
        <nav className="nav" aria-label="Main">
          <div className="nav-section">Monitor</div>
          {link("/", "Dashboard")}
          {link("/alerts", "Alerts", openAlerts, critical > 0)}
          {link("/flows", "Flow explorer")}
          <div className="nav-section">Policy</div>
          {link("/approvals", "Approvals", dash?.pending_drafts, (dash?.pending_drafts ?? 0) > 0)}
          {link("/rules", "Rules")}
          {link("/bundles", "Bundles & rollout")}
          <div className="nav-section">Operate</div>
          {link("/fleet", "Fleet")}
          {can("audit:read") && link("/audit", "Audit trail")}
          {can("users:manage") && link("/users", "Users")}
          {can("integrations:manage") && link("/integrations", "Integrations")}
          {link("/billing", "Billing")}
          {link("/settings", "Settings")}
        </nav>
        <div className="sidebar-foot">
          <div className="who"><span title={me?.email}>{me?.email}</span><span className="badge c-info">{me?.role}</span></div>
          <div className="row">
            <button className="small" onClick={toggleTheme}>{theme === "dark" ? "Light" : "Dark"} theme</button>
            <button className="small ghost" onClick={logout}>Sign out</button>
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="menu-btn small" onClick={() => setOpen(!open)} aria-label="Menu">☰</button>
          <span className="muted mono" style={{ fontSize: 12 }}>{loc.pathname}</span>
          <span className="spacer" />
          {dash && (
            <span className="row" style={{ fontSize: 12 }}>
              <span className={`badge dot c-${dash.advisor_mode === "online" ? "llm" : dash.advisor_mode === "degraded" ? "alert" : "info"}`}>
                Tier 3 {dash.advisor_mode}
              </span>
              <span className="badge dot c-active">bundle v{dash.bundle_version}</span>
              <span className={`badge dot ${dash.nodes.online ? "c-online" : "c-offline"}`}>
                {dash.nodes.online}/{dash.nodes.total} nodes
              </span>
            </span>
          )}
        </header>
        <main className="page"><Outlet /></main>
      </div>
    </div>
  );
}
