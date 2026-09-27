import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Badge, Card, Drawer, Empty, ErrorBox, Loading, Meter, Modal, PageHead } from "../components/ui";
import { api, type DraftRow, type Mode, type Rule, type RuleMatch, type Simulation } from "../lib/api";
import { ago, dateTime, human, matchSummary, pct } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

export function Approvals() {
  const { draftId } = useParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const [status, setStatus] = useState("pending");
  const [creating, setCreating] = useState(false);
  const { data, error, reload } = useApi<DraftRow[]>(`/drafts${status ? `?status=${status}` : ""}`, { poll: 10000 });

  return (
    <>
      <PageHead
        title="Approvals"
        desc="Proposed rules from the Tier 3 advisor and operators. Every draft is simulated against recent traffic; nothing changes enforcement until a human approves it."
        actions={can("rules:author") && <button className="primary" onClick={() => setCreating(true)}>New rule draft</button>}
      />
      <Card pad={false} title={
        <div className="segmented">
          {["pending", "approved", "rejected", ""].map((s) => <button key={s} className={status === s ? "on" : ""} onClick={() => setStatus(s)}>{s || "all"}</button>)}
        </div>
      }>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : !data.length ? (
          <Empty>{status === "pending" ? "Nothing awaiting approval." : "No drafts."}</Empty>
        ) : (
          <div className="table-wrap"><table>
            <thead><tr><th>Status</th><th>Proposed rule</th><th>Action</th><th>Source</th><th className="num">Confidence</th><th className="num">Blast radius</th><th>Created</th></tr></thead>
            <tbody>
              {data.map((d) => {
                const sim = d.draft.simulation;
                return (
                  <tr key={d.id} className={`clickable ${d.id === draftId ? "selected" : ""}`} onClick={() => nav(`/approvals/${d.id}`)}>
                    <td><Badge kind={d.status} /></td>
                    <td className="truncate">{d.draft.name}</td>
                    <td><Badge kind={d.draft.action} /></td>
                    <td><Badge kind={d.draft.source}>{d.draft.source === "llm" ? "Claude" : d.draft.source}</Badge></td>
                    <td className="num">{pct(d.draft.confidence, 0)}</td>
                    <td className="num" style={{ color: sim?.exceeds_threshold ? "var(--block)" : undefined }}>{sim ? pct(sim.blast_radius, 2) : "—"}</td>
                    <td className="muted">{ago(d.created_at)} · {d.created_by}</td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        )}
      </Card>
      {draftId && <DraftDrawer id={draftId} onClose={() => nav("/approvals")} onChange={reload} />}
      {creating && <NewDraftModal onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); reload(); nav(`/approvals/${id}`); }} />}
    </>
  );
}

function SimulationView({ sim }: { sim: Simulation }) {
  return (
    <div className="stack">
      <div className="row"><h3>Simulation</h3><span className="faint">replayed against {sim.flows_evaluated.toLocaleString()} recent flows</span></div>
      <Meter value={sim.threshold ? Math.min(1, sim.blast_radius / (sim.threshold * 2)) : 0} warn={sim.exceeds_threshold} />
      <dl className="kv">
        <dt>Blast radius</dt><dd><b className="mono" style={{ color: sim.exceeds_threshold ? "var(--block)" : "var(--allow)" }}>{pct(sim.blast_radius, 3)}</b> of legitimate traffic <span className="faint">(threshold {pct(sim.threshold, 2)})</span></dd>
        <dt>Flows matched</dt><dd className="mono">{sim.flows_matched} ({sim.legitimate_matched} legitimate)</dd>
        <dt>Would block</dt><dd className="mono">{sim.would_block}</dd>
        <dt>Sources / destinations</dt><dd className="mono">{sim.affected_sources} / {sim.affected_destinations}</dd>
      </dl>
      {sim.exceeds_threshold && <div className="callout danger">This rule would affect more legitimate traffic than the configured threshold. Enforcing it requires explicit acknowledgement. Consider alert-only mode or narrowing the match.</div>}
    </div>
  );
}

function DraftDrawer({ id, onClose, onChange }: { id: string; onClose: () => void; onChange: () => void }) {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: d, error, reload } = useApi<DraftRow>(`/drafts/${id}`);
  const [mode, setMode] = useState<Mode>("alert_only");
  const [note, setNote] = useState("");
  const [ack, setAck] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");

  const approve = async () => {
    const r = await run(() => api<Rule>(`/drafts/${id}/approve`, { method: "POST", json: { mode, note, acknowledge_blast_radius: ack } }),
      "Rule approved — new bundle published");
    if (r) { reload(); onChange(); }
  };
  const reject = async () => {
    if (await run(() => api(`/drafts/${id}/reject`, { method: "POST", json: { reason } }), "Draft rejected")) {
      setRejecting(false); reload(); onChange();
    }
  };

  return (
    <Drawer onClose={onClose} title={d?.draft.name ?? "Draft"} sub={d && (
      <span className="row"><Badge kind={d.status} /><Badge kind={d.draft.source}>{d.draft.source === "llm" ? "Drafted by Claude" : `${d.draft.source} draft`}</Badge><span>{dateTime(d.created_at)}</span></span>
    )}>
      {error && <ErrorBox error={error} />}
      {!d ? <Loading /> : (
        <>
          <div className={`callout ${d.draft.source === "llm" ? "ai" : ""}`}>
            <h3 style={{ marginBottom: 6 }}>Rationale</h3>{d.draft.rationale}
          </div>
          <dl className="kv">
            <dt>Action</dt><dd><Badge kind={d.draft.action} /></dd>
            <dt>Priority</dt><dd className="mono">{d.draft.priority}</dd>
            <dt>Confidence</dt><dd className="mono">{pct(d.draft.confidence, 0)}</dd>
            <dt>Match</dt><dd><ul className="list-plain mono">{matchSummary(d.draft.match as Record<string, unknown>).map((m) => <li key={m}>{m}</li>)}</ul></dd>
            <dt>Evidence</dt><dd>{d.draft.evidence_flow_ids.length} flows{d.alert_id && <> · <Link to={`/alerts/${d.alert_id}`}>alert #{d.alert_id}</Link></>}</dd>
          </dl>
          {d.draft.simulation && <SimulationView sim={d.draft.simulation} />}
          {d.status === "pending" && can("rules:approve") && (
            <Card title="Decision">
              <div className="stack">
                <div className="row">
                  <span className="muted">Deploy as</span>
                  <div className="segmented">
                    <button className={mode === "alert_only" ? "on" : ""} onClick={() => setMode("alert_only")}>Alert-only</button>
                    <button className={mode === "enforce" ? "on" : ""} onClick={() => setMode("enforce")}>Enforce</button>
                  </div>
                </div>
                {mode === "enforce" && d.draft.simulation?.exceeds_threshold && (
                  <label className="check"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />I have reviewed the blast radius and accept it</label>
                )}
                <label className="field">Approval note (audited)<input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. confirmed with app owner" /></label>
                <div className="row">
                  <button className="primary" disabled={busy} onClick={approve}>Approve & publish</button>
                  <button className="danger" disabled={busy} onClick={() => setRejecting(true)}>Reject</button>
                </div>
              </div>
            </Card>
          )}
          {d.status === "pending" && !can("rules:approve") && <div className="callout">Your role can review but not approve drafts. An approver or admin must decide.</div>}
          {d.status !== "pending" && (
            <div className="callout">
              {human(d.status)} by <b>{d.decided_by}</b> {ago(d.decided_at)}{d.rule_id && <> as <Link to="/rules" className="mono">{d.rule_id}</Link></>}.
              {d.decision_note && <div className="muted" style={{ marginTop: 4 }}>“{d.decision_note}”</div>}
            </div>
          )}
          {rejecting && (
            <Modal title="Reject draft" onClose={() => setRejecting(false)} footer={<>
              <button onClick={() => setRejecting(false)}>Cancel</button>
              <button className="danger" disabled={!reason.trim() || busy} onClick={reject}>Reject</button></>}>
              <label className="field">Reason (recorded in the audit trail)<textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
            </Modal>
          )}
        </>
      )}
    </Drawer>
  );
}

const LIST_FIELDS: [keyof RuleMatch, string, string][] = [
  ["src_cidrs", "Source CIDRs", "203.0.113.7/32"],
  ["dst_cidrs", "Destination CIDRs", "10.30.0.0/24"],
  ["dst_ports", "Destination ports", "22, 3389"],
  ["protocols", "Protocols", "tcp, udp"],
  ["sni_suffixes", "TLS SNI suffixes", "evil.example"],
  ["dns_suffixes", "DNS suffixes", "tunnel.example"],
  ["http_path_prefixes", "HTTP path prefixes", "/wp-admin"],
  ["labels", "Threat labels", "sql_injection, c2_beacon"],
];

function NewDraftModal({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const { run, busy } = useAction();
  const [name, setName] = useState("");
  const [rationale, setRationale] = useState("");
  const [action, setAction] = useState("drop");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<Simulation | null>(null);

  const match = (): RuleMatch => {
    const m: Record<string, unknown> = {};
    for (const [k] of LIST_FIELDS) {
      const vals = (fields[k] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
      if (vals.length) m[k] = k === "dst_ports" ? vals.map(Number) : vals;
    }
    if (fields.labels) m.min_label_confidence = 0.8;
    return m as RuleMatch;
  };

  return (
    <Modal title="New rule draft" onClose={onClose} footer={<>
      <button onClick={onClose}>Cancel</button>
      <button disabled={busy} onClick={async () => {
        const r = await run(() => api<Simulation>("/drafts/simulate", { method: "POST", json: { action, match: match() } }));
        if (r) setPreview(r);
      }}>Simulate</button>
      <button className="primary" disabled={busy || !name || !rationale} onClick={async () => {
        const r = await run(() => api<DraftRow>("/drafts", { method: "POST", json: { name, rationale, action, match: match() } }), "Draft created");
        if (r) onCreated(r.id);
      }}>Create draft</button>
    </>}>
      <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} maxLength={120} /></label>
      <label className="field">Rationale (shown to approvers)<textarea rows={3} value={rationale} onChange={(e) => setRationale(e.target.value)} /></label>
      <label className="field">Action
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          {["alert", "rate_limit", "drop", "quarantine", "allow"].map((a) => <option key={a} value={a}>{human(a)}</option>)}
        </select>
      </label>
      <p className="faint" style={{ margin: 0, fontSize: 12 }}>All filled criteria must match (AND). Separate multiple values with commas.</p>
      {LIST_FIELDS.map(([k, label, ph]) => (
        <label key={k} className="field">{label}<input placeholder={ph} value={fields[k] ?? ""} onChange={(e) => setFields({ ...fields, [k]: e.target.value })} /></label>
      ))}
      {preview && <SimulationView sim={preview} />}
    </Modal>
  );
}
