import { useState } from "react";
import { Async, Badge, Card, Modal } from "../components/ui";
import { api } from "../lib/api";
import { dateTime } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

export interface ChangeWindow {
  id: number; cidrs: string[]; starts_at: number; ends_at: number; reason: string;
  created_by: string; created_at: number; cancelled_at: number | null;
  status: "scheduled" | "active" | "ended" | "cancelled";
}

const STATUS_KIND: Record<ChangeWindow["status"], string> = {
  active: "alert_only", scheduled: "pending", ended: "superseded", cancelled: "rejected",
};

/** Planned changes during which Tier 1 anomaly scores for some networks are damped. */
export function ChangeWindows() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const [showPast, setShowPast] = useState(false);
  const { data, error, reload } = useApi<ChangeWindow[]>(`/change-windows?include_past=${showPast}`, { poll: 30000 });
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ cidrs: "", minutes: "60", start: "", reason: "" });

  const create = async () => {
    const starts = form.start ? new Date(form.start).getTime() / 1000 : undefined;
    const body = {
      cidrs: form.cidrs.split(/[\s,]+/).filter(Boolean),
      duration_minutes: Number(form.minutes),
      reason: form.reason,
      ...(starts ? { starts_at: starts } : {}),
    };
    if (await run(() => api("/change-windows", { method: "POST", json: body }), "Change window created")) {
      setCreating(false);
      setForm({ cidrs: "", minutes: "60", start: "", reason: "" });
      reload();
    }
  };

  return (
    <Card
      title="Change windows"
      actions={<div className="row">
        <label className="check"><input type="checkbox" checked={showPast} onChange={(e) => setShowPast(e.target.checked)} />Show past</label>
        {can("rules:author") && <button className="small" onClick={() => setCreating(true)}>New window</button>}
      </div>}
      pad={false}
    >
      <p className="muted" style={{ margin: "12px 16px 0" }}>
        During a planned change (deployment, backup, migration), Tier 1 anomaly scores for the listed networks are damped so it does not page anyone.
        Tier 2 labels and rules still apply, so a real attack is still caught. At most 24 hours; nothing broader than a /16 (IPv4) or /48 (IPv6).
      </p>
      <Async error={error} data={data}>{(rows) => rows.length === 0 ? (
        <div className="empty">{showPast ? "No change windows yet." : "No active or scheduled change windows."}</div>
      ) : (
        <div className="table-wrap"><table>
          <thead><tr><th>Status</th><th>Networks</th><th>From</th><th>Until</th><th>Reason</th><th>By</th><th /></tr></thead>
          <tbody>
            {rows.map((w) => (
              <tr key={w.id}>
                <td><Badge kind={STATUS_KIND[w.status]}>{w.status}</Badge></td>
                <td className="mono">{w.cidrs.join(", ")}</td>
                <td className="mono muted">{dateTime(w.starts_at)}</td>
                <td className="mono muted">{dateTime(w.ends_at)}</td>
                <td className="truncate">{w.reason}</td>
                <td className="muted">{w.created_by}</td>
                <td>{can("rules:author") && (w.status === "active" || w.status === "scheduled") && (
                  <button className="small danger" disabled={busy} onClick={async () => {
                    if (await run(async () => { await api(`/change-windows/${w.id}`, { method: "DELETE" }); return true; }, "Change window cancelled")) reload();
                  }}>Cancel</button>
                )}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}</Async>
      {creating && (
        <Modal title="New change window" onClose={() => setCreating(false)} footer={<>
          <button onClick={() => setCreating(false)}>Cancel</button>
          <button className="primary" disabled={busy || !form.cidrs.trim() || !form.reason.trim()} onClick={create}>Create</button>
        </>}>
          <label className="field">Networks (IPs or CIDRs, comma-separated)<input value={form.cidrs} placeholder="10.30.0.0/24, 10.20.0.15" onChange={(e) => setForm({ ...form, cidrs: e.target.value })} /></label>
          <label className="field">Start (leave empty for now)<input type="datetime-local" value={form.start} onChange={(e) => setForm({ ...form, start: e.target.value })} /></label>
          <label className="field">Duration<select value={form.minutes} onChange={(e) => setForm({ ...form, minutes: e.target.value })}>
              {[["30", "30 minutes"], ["60", "1 hour"], ["120", "2 hours"], ["240", "4 hours"], ["480", "8 hours"], ["1440", "24 hours"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <label className="field">Reason (audited)<input value={form.reason} maxLength={300} placeholder="e.g. payments-api deploy" onChange={(e) => setForm({ ...form, reason: e.target.value })} /></label>
        </Modal>
      )}
    </Card>
  );
}
