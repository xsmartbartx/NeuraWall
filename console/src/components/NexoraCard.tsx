import { Badge, Card, ErrorBox, Loading } from "./ui";
import { api } from "../lib/api";
import { ago } from "../lib/format";
import { useAction, useApi } from "../lib/hooks";

interface NexoraStatus {
  linked: boolean; organisation: string | null; api_url: string | null; sync_interval_seconds: number;
  last_ok: number | null; last_try: number | null; error: string | null; plan: string; plan_valid_until: number | null;
  events_enabled: boolean; events_pending: number;
}

export function NexoraCard() {
  const { data: n, error, reload } = useApi<NexoraStatus>("/nexora/status", { poll: 30000 });
  const { run, busy } = useAction();
  if (error) return <Card title="NEXORA"><ErrorBox error={error} /></Card>;
  if (!n) return <Card title="NEXORA"><Loading /></Card>;
  if (!n.linked) return <Card title="NEXORA"><p className="muted" style={{ margin: 0 }}>This installation is not linked to a NEXORA organisation. Set <code>NEURAWALL_NEXORA__API_KEY</code> to link it: the plan then comes from NEXORA.</p></Card>;
  const state = n.error ? (n.last_ok ? "grace" : "error") : "linked";
  return (
    <Card title={<div className="row"><h2>NEXORA</h2><Badge kind={state === "linked" ? "active" : state === "grace" ? "alert" : "revoked"} dot>{state === "linked" ? "linked" : state === "grace" ? "using last known plan" : "not synced"}</Badge></div>}>
      <dl className="kv">
        <dt>Organisation</dt><dd className="mono">{n.organisation ?? "—"}</dd>
        <dt>Plan</dt><dd className="mono">{n.plan}</dd>
        <dt>Last sync</dt><dd>{n.last_ok ? ago(n.last_ok) : "never"}</dd>
        <dt>Usage events</dt><dd>{n.events_enabled ? `${n.events_pending} waiting to send` : "off"}</dd>
        <dt>Plan valid until</dt><dd>{n.plan_valid_until ? new Date(n.plan_valid_until * 1000).toLocaleString() : "—"}</dd>
      </dl>
      {n.error && <div className="callout warn" style={{ marginTop: 12 }} role="status">Last sync failed: {n.error}. Enforcement is not affected; the last known plan keeps applying until it expires.</div>}
      <div style={{ marginTop: 12 }}><button disabled={busy} onClick={async () => { await run(() => api("/nexora/sync", { method: "POST" }), "Synced with NEXORA"); reload(); }}>Sync now</button></div>
    </Card>
  );
}

