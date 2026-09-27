import { useState } from "react";
import { Badge, Card, Drawer, ErrorBox, Loading, Modal, PageHead } from "../components/ui";
import { api, type HygieneFinding, type Rule } from "../lib/api";
import { dateTime, human, matchSummary } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

export function Rules() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data, error, reload } = useApi<Rule[]>("/rules");
  const { data: hygiene, reload: reloadHygiene } = useApi<HygieneFinding[]>("/rules/hygiene");
  const [selected, setSelected] = useState<Rule | null>(null);
  const [deleting, setDeleting] = useState<Rule | null>(null);
  const canEdit = can("rules:approve");
  const findingsFor = (id: string) => hygiene?.filter((h) => h.rule_id === id) ?? [];

  const patch = async (r: Rule, body: Partial<Rule>, msg: string) => {
    const updated = await run(() => api<Rule>(`/rules/${r.id}`, { method: "PATCH", json: body }), msg);
    if (updated) { reload(); reloadHygiene(); if (selected?.id === r.id) setSelected(updated); }
  };

  return (
    <>
      <PageHead title="Rules" desc="The approved rule set, evaluated in priority order (lowest first; first match wins). Every change is audited and publishes a new signed bundle." />
      {hygiene && hygiene.length > 0 && (
        <div className="callout warn">
          <b>Rule-set hygiene:</b> {hygiene.length} finding{hygiene.length > 1 ? "s" : ""}.
          <ul className="list-plain" style={{ marginTop: 6 }}>{hygiene.map((h, i) => <li key={i}><span className="mono">{h.rule_id}</span> — <b>{human(h.kind)}</b>: {h.detail}</li>)}</ul>
        </div>
      )}
      <Card pad={false}>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>ID</th><th className="num">Priority</th><th>Name</th><th>Action</th><th>Mode</th><th>Match</th><th>Enabled</th></tr></thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.id} className={`clickable ${selected?.id === r.id ? "selected" : ""}`} onClick={() => setSelected(r)} style={{ opacity: r.enabled ? 1 : 0.55 }}>
                  <td className="mono">{r.id}{findingsFor(r.id).length > 0 && <span title="hygiene finding" style={{ color: "var(--alert)" }}> ●</span>}</td>
                  <td className="num">{r.priority}</td>
                  <td className="truncate">{r.name}</td>
                  <td><Badge kind={r.action} /></td>
                  <td><Badge kind={r.mode} /></td>
                  <td className="mono truncate faint" style={{ maxWidth: 300 }}>{matchSummary(r.match as Record<string, unknown>).join(" · ")}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" checked={r.enabled} disabled={!canEdit || busy} aria-label={`Enable ${r.id}`}
                      onChange={() => patch(r, { enabled: !r.enabled }, `${r.id} ${r.enabled ? "disabled" : "enabled"}`)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      {selected && (
        <Drawer onClose={() => setSelected(null)} title={`${selected.id} · ${selected.name}`}
          sub={<span className="row"><Badge kind={selected.action} /><Badge kind={selected.mode} />{!selected.enabled && <Badge kind="offline">disabled</Badge>}<span>v{selected.version}</span></span>}>
          <div className="callout"><h3 style={{ marginBottom: 6 }}>Rationale</h3>{selected.rationale}</div>
          {selected.description && <p className="muted" style={{ margin: 0 }}>{selected.description}</p>}
          <dl className="kv">
            <dt>Priority</dt><dd className="mono">{selected.priority}</dd>
            <dt>Match</dt><dd><ul className="list-plain mono">{matchSummary(selected.match as Record<string, unknown>).map((m) => <li key={m}>{m}</li>)}</ul></dd>
            <dt>Authored by</dt><dd>{selected.created_by}</dd>
            <dt>Approved by</dt><dd>{selected.approved_by ?? "—"}</dd>
            <dt>Created</dt><dd>{dateTime(selected.created_at)}</dd>
          </dl>
          {findingsFor(selected.id).map((h, i) => <div key={i} className="callout warn"><b>{human(h.kind)}</b>: {h.detail}</div>)}
          {canEdit && (
            <div className="row">
              <button disabled={busy} onClick={() => patch(selected, { mode: selected.mode === "enforce" ? "alert_only" : "enforce" },
                `${selected.id} switched to ${selected.mode === "enforce" ? "alert-only" : "enforce"}`)}>
                Switch to {selected.mode === "enforce" ? "alert-only" : "enforce"}
              </button>
              <button disabled={busy} onClick={() => patch(selected, { enabled: !selected.enabled }, "Rule updated")}>{selected.enabled ? "Disable" : "Enable"}</button>
              <button className="danger" disabled={busy} onClick={() => setDeleting(selected)}>Delete</button>
            </div>
          )}
          <details><summary className="muted">Raw rule JSON</summary><pre className="code" style={{ marginTop: 8 }}>{JSON.stringify(selected, null, 2)}</pre></details>
        </Drawer>
      )}
      {deleting && (
        <Modal title={`Delete ${deleting.id}?`} onClose={() => setDeleting(null)} footer={<>
          <button onClick={() => setDeleting(null)}>Cancel</button>
          <button className="danger" disabled={busy} onClick={async () => {
            if (await run(async () => { await api(`/rules/${deleting.id}`, { method: "DELETE" }); return true; }, `${deleting.id} deleted`)) {
              setDeleting(null); setSelected(null); reload(); reloadHygiene();
            }
          }}>Delete rule</button></>}>
          <p style={{ margin: 0 }}>“{deleting.name}” will be removed and a new bundle published to the fleet. The deletion is recorded in the audit trail; rolling back the bundle restores it.</p>
        </Modal>
      )}
    </>
  );
}
