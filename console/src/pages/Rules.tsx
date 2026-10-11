import { useState } from "react";
import { Async, Badge, Card, Drawer, Modal, PageHead, activatable } from "../components/ui";
import { api, type HygieneFinding, type Rule, type RuleStats, type Simulation } from "../lib/api";
import { ago, dateTime, human, matchSummary } from "../lib/format";
import { SimulationView } from "./Approvals";
import { useAction, useApi, useAuth } from "../lib/hooks";

export function Rules() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data, error, reload } = useApi<Rule[]>("/rules");
  const { data: hygiene, reload: reloadHygiene } = useApi<HygieneFinding[]>("/rules/hygiene");
  const { data: stats } = useApi<RuleStats>("/rules/stats", { poll: 30000 });
  const days = stats ? Math.round(stats.hours / 24) : 7;
  const [selected, setSelected] = useState<Rule | null>(null);
  const [cleanup, setCleanup] = useState<HygieneFinding | null>(null);
  const [deleting, setDeleting] = useState<Rule | null>(null);
  const canEdit = can("rules:approve");
  const disableRedundant = async (rule: Rule | undefined) => {
    if (rule) {
      await patch(rule, { enabled: false }, `${rule.id} disabled`);
    }
    setCleanup(null);
    reloadHygiene();
  };
  const lastMatch = (id: string) => {
    if (!stats) return "…";
    const m = stats.rules[id];
    if (!m) return <span className="faint" title={`No flow matched this rule in the last ${days} days`}>never</span>;
    return ago(m.last_match);
  };
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
          <ul className="list-plain" style={{ marginTop: 6 }}>{hygiene.map((h) => <li key={`${h.rule_id}-${h.kind}-${h.related_rule_id ?? ""}`}><span className="mono">{h.rule_id}</span> — <b>{human(h.kind)}</b>: {h.detail}{canEdit && (h.kind === "redundant" || h.kind === "shadowed") && (data ?? []).find((r) => r.id === h.rule_id)?.enabled && <> <button className="small" disabled={busy} onClick={() => setCleanup(h)}>Clean up…</button></>}</li>)}</ul>
        </div>
      )}
      <Card pad={false}>
        <Async error={error} data={data}>{(data) => (
          <div className="table-wrap"><table>
            <thead><tr><th>ID</th><th className="num">Priority</th><th>Name</th><th>Action</th><th>Mode</th><th>Match</th><th className="num">Matches ({days}d)</th><th>Last match</th><th>Enabled</th></tr></thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.id} className={`clickable ${selected?.id === r.id ? "selected" : ""}`} onClick={() => setSelected(r)} {...activatable(() => setSelected(r))} style={{ opacity: r.enabled ? 1 : 0.55 }}>
                  <td className="mono">{r.id}{findingsFor(r.id).length > 0 && <span title="hygiene finding" style={{ color: "var(--alert)" }}> ●</span>}</td>
                  <td className="num">{r.priority}</td>
                  <td className="truncate">{r.name}</td>
                  <td><Badge kind={r.action} /></td>
                  <td><Badge kind={r.mode} /></td>
                  <td className="mono truncate faint" style={{ maxWidth: 300 }}>{matchSummary(r.match as Record<string, unknown>).join(" · ")}</td>
                  <td className="num">{stats ? (stats.rules[r.id]?.matches ?? 0).toLocaleString() : "…"}</td>
                  <td className="muted">{lastMatch(r.id)}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" checked={r.enabled} disabled={!canEdit || busy} aria-label={`Enable ${r.id}`}
                      onChange={() => patch(r, { enabled: !r.enabled }, `${r.id} ${r.enabled ? "disabled" : "enabled"}`)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}</Async>
      </Card>
      {cleanup && (() => {
        const rule = (data ?? []).find((r) => r.id === cleanup.rule_id);
        const n = stats?.rules[cleanup.rule_id]?.matches ?? 0;
        return (
          <Modal title={`Disable ${cleanup.rule_id}?`} onClose={() => setCleanup(null)} footer={<>
            <button onClick={() => setCleanup(null)}>Cancel</button>
            <button className="primary" disabled={busy || !rule} onClick={() => disableRedundant(rule)}>Disable rule</button>
          </>}>
            <p style={{ margin: 0 }}>{cleanup.detail}</p>
            <p style={{ margin: 0 }}>Because the earlier rule takes all of this rule's traffic first, disabling it changes no verdict. It stays in the list, and you can turn it back on. Disabling publishes a new signed bundle and is recorded in the audit trail.</p>
            {n > 0
              ? <output className="callout warn">It did match {n.toLocaleString()} flow{n === 1 ? "" : "s"} in the last {days} days. That can happen if the covering rule was added or enabled recently. Check before you disable it.</output>
              : <output className="callout">No flow matched it in the last {days} days, which agrees with the finding.</output>}
          </Modal>
        );
      })()}
      {selected && (
        <Drawer onClose={() => setSelected(null)} title={`${selected.id} · ${selected.name}`}
          sub={<span className="row"><Badge kind={selected.action} /><Badge kind={selected.mode} />{!selected.enabled && <Badge kind="offline">disabled</Badge>}<span>v{selected.version}</span></span>}>
          <div className="callout"><h3 style={{ marginBottom: 6 }}>Rationale</h3>{selected.rationale}</div>
          <RuleImpact ruleId={selected.id} matches={stats?.rules[selected.id]?.matches ?? 0} days={days} />
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

/** The rule replayed against recent traffic, on demand (it replays up to 20,000 flows). */
function RuleImpact({ ruleId, matches, days }: Readonly<{ ruleId: string; matches: number; days: number }>) {
  const { run, busy } = useAction();
  const [sim, setSim] = useState<Simulation | null>(null);
  return (
    <Card title="Impact on recent traffic">
      <p className="muted" style={{ marginTop: 0 }}>
        {matches === 0 ? `No flow matched this rule in the last ${days} days.` : `${matches.toLocaleString()} flows matched this rule in the last ${days} days.`}
      </p>
      {sim ? <SimulationView sim={sim} /> : (
        <button disabled={busy} onClick={async () => { const r = await run(() => api<Simulation>(`/rules/${ruleId}/impact`)); if (r) setSim(r); }}>
          {busy ? "Replaying…" : "Replay against recent traffic"}
        </button>
      )}
    </Card>
  );
}
