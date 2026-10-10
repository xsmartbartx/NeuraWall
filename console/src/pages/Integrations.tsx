import { useState } from "react";
import { Badge, Card, Empty, ErrorBox, Loading, Modal, PageHead } from "../components/ui";
import { NexoraCard } from "../components/NexoraCard";
import { SecretReveal, Toggle } from "../components/controls";
import { api, type Channel, type Delivery, type Severity } from "../lib/api";
import { ago, human } from "../lib/format";
import { useAction, useApi, useToast } from "../lib/hooks";

const EVENTS: [string, string][] = [
  ["alert.created", "A new alert is raised"],
  ["draft.pending", "A rule draft needs approval"],
];
const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

interface Form { name: string; url: string; events: string[]; min_severity: Severity }
const BLANK: Form = { name: "", url: "", events: ["alert.created", "draft.pending"], min_severity: "high" };

export function Integrations() {
  const { data: channels, error, reload } = useApi<Channel[]>("/notifications/channels", { poll: 15000 });
  const { data: deliveries, reload: reloadDeliveries } = useApi<Delivery[]>("/notifications/deliveries", { poll: 15000 });
  const { run, busy } = useAction();
  const toast = useToast();
  const [editing, setEditing] = useState<{ id: number | null; form: Form } | null>(null);
  const [secret, setSecret] = useState<{ name: string; value: string } | null>(null);
  const [deleting, setDeleting] = useState<Channel | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const names = new Map((channels ?? []).map((c) => [c.id, c.name]));

  const save = async () => {
    if (!editing) return;
    setFormError(null);
    const { id, form } = editing;
    try {
      const res = await api<Channel>(id === null ? "/notifications/channels" : `/notifications/channels/${id}`, {
        method: id === null ? "POST" : "PATCH",
        json: id === null ? form : { ...form, url: form.url || undefined },
      });
      setEditing(null);
      if (res.signing_secret) setSecret({ name: res.name, value: res.signing_secret });
      reload();
    } catch (e) { setFormError((e as Error).message); }
  };

  const toggleEvent = (f: Form, ev: string): Form => ({ ...f, events: f.events.includes(ev) ? f.events.filter((x) => x !== ev) : [...f.events, ev] });

  return (
    <>
      <PageHead title="Integrations" desc="Link this installation to your NEXORA organisation and send alerts to the tools your team already watches."
        actions={<button className="primary" onClick={() => { setFormError(null); setEditing({ id: null, form: BLANK }); }}>Add webhook</button>} />
      <NexoraCard />
      <Card pad={false} title="Webhooks">
        {error ? <ErrorBox error={error} /> : !channels ? <Loading /> : channels.length === 0 ? (
          <Empty>No webhooks yet. Add one to send new alerts and pending approvals as signed JSON to Slack, Teams or any receiver that accepts a webhook.</Empty>
        ) : (
          <div className="table-wrap"><table>
            <thead><tr><th>Name</th><th>Sends to</th><th>When</th><th>Last delivery</th><th>State</th><th></th></tr></thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td className="mono">{c.url_hint}</td>
                  <td>{c.events.map((e) => human(e.replace(".", " "))).join(", ")}{c.events.includes("alert.created") && <span className="faint"> · {c.min_severity}+</span>}</td>
                  <td>{c.last_delivery
                    ? <><Badge kind={c.last_delivery.status === "sent" ? "active" : c.last_delivery.status === "dead" ? "revoked" : "pending"}>{c.last_delivery.status === "sent" ? "delivered" : c.last_delivery.status === "dead" ? "failed" : "retrying"}</Badge> <span className="faint">{ago(c.last_delivery.at)}</span></>
                    : <span className="faint">never</span>}</td>
                  <td><Toggle checked={c.active} disabled={busy} label={c.active ? "On" : "Paused"}
                    onChange={async (v) => { await run(() => api(`/notifications/channels/${c.id}`, { method: "PATCH", json: { active: v } })); reload(); }} /></td>
                  <td className="row" style={{ flexWrap: "nowrap" }}>
                    <button className="small" disabled={busy} onClick={async () => {
                      const r = await run(() => api<{ ok: boolean; error: string | null }>(`/notifications/channels/${c.id}/test`, { method: "POST" }));
                      if (r) { toast(r.ok ? "Test message delivered" : `Test failed: ${r.error}`, r.ok ? "ok" : "error"); reloadDeliveries(); reload(); }
                    }}>Send test</button>
                    <button className="small" onClick={() => { setFormError(null); setEditing({ id: c.id, form: { name: c.name, url: "", events: c.events, min_severity: c.min_severity } }); }}>Edit</button>
                    <button className="small danger" onClick={() => setDeleting(c)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      <Card pad={false} title="Recent deliveries">
        {!deliveries ? <Loading /> : deliveries.length === 0 ? <Empty>Nothing has been sent yet.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>When</th><th>Webhook</th><th>Event</th><th>Result</th><th className="num">Tries</th></tr></thead>
            <tbody>
              {deliveries.slice(0, 50).map((d) => (
                <tr key={d.id}>
                  <td className="muted">{ago(d.sent_at ?? d.created_at)}</td>
                  <td>{names.get(d.channel_id) ?? `#${d.channel_id}`}</td>
                  <td>{human(d.event_type.replace(".", " "))} <span className="faint mono">{d.ref}</span></td>
                  <td>{d.status === "sent" ? <Badge kind="active">delivered</Badge> : d.status === "dead" ? <Badge kind="revoked">gave up</Badge> : <Badge kind="pending">retrying</Badge>} {d.error && <span className="faint">{d.error}</span>}</td>
                  <td className="num">{d.attempts}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>

      {editing && (
        <Modal title={editing.id === null ? "Add webhook" : "Edit webhook"} onClose={() => setEditing(null)} footer={<>
          <button onClick={() => setEditing(null)}>Cancel</button>
          <button className="primary" disabled={busy || !editing.form.name || (editing.id === null && !editing.form.url) || editing.form.events.length === 0} onClick={save}>{editing.id === null ? "Create webhook" : "Save"}</button>
        </>}>
          <label className="field">Name<input value={editing.form.name} maxLength={80} onChange={(e) => setEditing({ ...editing, form: { ...editing.form, name: e.target.value } })} autoFocus /></label>
          <label className="field">{editing.id === null ? "URL" : "New URL (leave empty to keep the current one)"}
            <input type="url" placeholder="https://hooks.example.com/…" value={editing.form.url} aria-invalid={Boolean(formError)} aria-describedby={formError ? "hook-error" : undefined}
              onChange={(e) => setEditing({ ...editing, form: { ...editing.form, url: e.target.value } })} />
          </label>
          <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="muted" style={{ fontSize: 12, fontWeight: 500, marginBottom: 6 }}>Send when</legend>
            {EVENTS.map(([ev, text]) => (
              <label key={ev} className="check"><input type="checkbox" checked={editing.form.events.includes(ev)} onChange={() => setEditing({ ...editing, form: toggleEvent(editing.form, ev) })} />{text}</label>
            ))}
          </fieldset>
          <label className="field">Alerts of at least this severity
            <select value={editing.form.min_severity} onChange={(e) => setEditing({ ...editing, form: { ...editing.form, min_severity: e.target.value as Severity } })}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{human(s)}</option>)}
            </select>
          </label>
          {editing.id !== null && <button type="button" className="small" disabled={busy} onClick={async () => {
            const r = await run(() => api<Channel>(`/notifications/channels/${editing.id}`, { method: "PATCH", json: { rotate_secret: true } }));
            if (r?.signing_secret) { setEditing(null); setSecret({ name: r.name, value: r.signing_secret }); reload(); }
          }}>Rotate signing secret</button>}
          <p className="faint" style={{ margin: 0, fontSize: 12 }}>Webhooks must use https and a public address. Each message is signed so the receiver can check it came from this server. Alert messages include the source and destination addresses.</p>
          {formError && <div id="hook-error" className="error-text" role="alert">{formError}</div>}
        </Modal>
      )}
      {secret && (
        <Modal title={`Signing secret for ${secret.name}`} onClose={() => setSecret(null)} footer={<></>}>
          <SecretReveal label="signing secret" secret={secret.value} onDone={() => setSecret(null)} />
          <p className="faint" style={{ margin: 0, fontSize: 12 }}>Each request carries <code>X-NeuraWall-Signature: sha256=HMAC(secret, "&lt;timestamp&gt;.&lt;body&gt;")</code> and <code>X-NeuraWall-Timestamp</code>.</p>
        </Modal>
      )}
      {deleting && (
        <Modal title={`Delete ${deleting.name}?`} onClose={() => setDeleting(null)} footer={<>
          <button onClick={() => setDeleting(null)}>Cancel</button>
          <button className="danger" disabled={busy} onClick={async () => { await run(() => api(`/notifications/channels/${deleting.id}`, { method: "DELETE" }), "Webhook deleted"); setDeleting(null); reload(); }}>Delete webhook</button>
        </>}>
          <p style={{ margin: 0 }}>Its delivery history is removed too. Nothing more will be sent to it.</p>
        </Modal>
      )}
    </>
  );
}
