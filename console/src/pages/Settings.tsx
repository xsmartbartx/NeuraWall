import { useState, type FormEvent } from "react";
import { Badge, Card, ErrorBox, Loading, PageHead } from "../components/ui";
import { api, setToken, type SystemInfo } from "../lib/api";
import { useAction, useApi, useAuth } from "../lib/hooks";

export function Settings() {
  const { me } = useAuth();
  const { data: s, error } = useApi<SystemInfo>("/system", { poll: 15000 });
  const { data: key } = useApi<{ key_id: string; public_key_pem: string }>("/pki/bundle-signing-key");
  const { run, busy } = useAction();
  const [pw, setPw] = useState({ current: "", next: "" });

  const change = async (e: FormEvent) => {
    e.preventDefault();
    const res = await run(() => api<{ access_token: string }>("/auth/password", { method: "POST", json: { current_password: pw.current, new_password: pw.next } }),
      "Password changed — other sessions signed out");
    if (res) { setToken(res.access_token); setPw({ current: "", next: "" }); }
  };

  return (
    <>
      <PageHead title="Settings" desc="System status and your account. Server configuration is managed via environment variables or the config file (see docs/configuration.md)." />
      {error && <ErrorBox error={error} />}
      {!s ? <Loading /> : (
        <div className="grid halves">
          <Card title="System">
            <dl className="kv">
              <dt>Version</dt><dd className="mono">{s.version}</dd>
              <dt>Environment</dt><dd><Badge kind={s.environment === "production" ? "active" : "pending"}>{s.environment}</Badge>{s.demo_mode && <> <Badge kind="info">demo traffic on</Badge></>}</dd>
              <dt>Host</dt><dd className="mono">{s.hostname}</dd>
              <dt>Uptime</dt><dd className="mono">{Math.floor(s.uptime_seconds / 3600)}h {Math.floor((s.uptime_seconds % 3600) / 60)}m</dd>
              <dt>Database</dt><dd className="mono">{s.database}</dd>
              <dt>Tier 1 baseline</dt><dd>{s.tier1_trained ? <Badge kind="active">trained</Badge> : <Badge kind="pending">warming up</Badge>}</dd>
              <dt>Four-eyes approval</dt><dd>{s.four_eyes ? <Badge kind="active">required</Badge> : <Badge kind="pending">not required</Badge>}</dd>
            </dl>
          </Card>
          <Card title="Tier 3 advisor">
            <dl className="kv">
              <dt>Mode</dt><dd><Badge kind={s.advisor.mode === "online" ? "llm" : s.advisor.mode === "degraded" || s.advisor.mode === "budget_reached" ? "alert" : "info"} dot>{s.advisor.mode === "budget_reached" ? "monthly budget reached" : s.advisor.mode}</Badge></dd>
              <dt>Provider</dt><dd className="mono">{s.advisor.provider}</dd>
              <dt>Model</dt><dd className="mono">{s.advisor.model ?? "offline heuristic advisor"}</dd>
              <dt>Budget left this hour</dt><dd className="mono">{s.advisor.budget_remaining}</dd>
              {s.advisor.last_error && <><dt>Last error</dt><dd style={{ color: "var(--block)" }}>{s.advisor.last_error}</dd></>}
            </dl>
            {s.advisor.mode === "budget_reached" && <div className="callout warn" style={{ marginTop: 12 }} role="status">The plan's Claude calls for this month are used. The offline advisor answers until the month ends (UTC). See Billing.</div>}
            {s.advisor.mode === "offline" && <div className="callout ai" style={{ marginTop: 12 }}>Set <code>ANTHROPIC_API_KEY</code> on the server to enable Claude-powered triage, rule drafting and incident narration. The offline advisor keeps every workflow available without it.</div>}
          </Card>
          <Card title="Bundle signing key">
            <p className="muted" style={{ marginTop: 0 }}>Nodes pin this key at enrollment and reject any bundle not signed by it. Confirm the key id matches what <code>neurawall agent enroll</code> printed.</p>
            {key && <><div className="row"><span className="muted">Key id</span><code style={{ fontSize: 14 }}>{key.key_id}</code></div>
              <pre className="code" style={{ marginTop: 10 }}>{key.public_key_pem}</pre></>}
          </Card>
          <Card title="Your account">
            <form className="stack" onSubmit={change}>
              <div className="muted">{me?.email} · <span className="mono">{me?.role}</span></div>
              <label className="field">Current password<input type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} required /></label>
              <label className="field">New password<input type="password" autoComplete="new-password" minLength={12} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} required /></label>
              <div><button type="submit" disabled={busy}>Change password</button></div>
            </form>
          </Card>
        </div>
      )}
    </>
  );
}
