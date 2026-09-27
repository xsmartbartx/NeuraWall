import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Badge, Card, Drawer, Empty, ErrorBox, Labels, Loading, PageHead, Pager } from "../components/ui";
import { api, type Alert, type FlowSummary, type Page } from "../lib/api";
import { ago, dateTime, human } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";
import { FlowTable } from "./Flows";

const STATUSES = ["open", "acknowledged", "resolved", "false_positive", ""];
const LIMIT = 50;

export function Alerts() {
  const { alertId } = useParams();
  const nav = useNavigate();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [offset, setOffset] = useState(0);
  const qs = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
  if (status) qs.set("status", status);
  if (severity) qs.set("severity", severity);
  const { data, error, reload } = useApi<Page<Alert>>(`/alerts?${qs}`, { poll: 10000 });

  return (
    <>
      <PageHead title="Alerts" desc="Related suspicious flows grouped by source and rule or label. Tier 3 triages high-severity and ambiguous alerts automatically." />
      <Card pad={false} title={
        <div className="row">
          <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }} aria-label="Status">
            {STATUSES.map((s) => <option key={s} value={s}>{s ? human(s) : "any status"}</option>)}
          </select>
          <select value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }} aria-label="Severity">
            {["", "critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s || "any severity"}</option>)}
          </select>
          {data && <span className="muted">{data.total} alerts</span>}
        </div>
      }>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : !data.items.length ? <Empty>No alerts match.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Severity</th><th>Status</th><th>Alert</th><th>Labels</th><th>Source</th><th className="num">Flows</th><th className="num">Blocked</th><th>Last seen</th></tr></thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id} className={`clickable ${String(a.id) === alertId ? "selected" : ""}`} onClick={() => nav(`/alerts/${a.id}`)}>
                  <td><Badge kind={a.severity} dot /></td>
                  <td><Badge kind={a.status} /></td>
                  <td className="truncate">{a.title}{a.summary_source === "llm" && <span className="badge c-ai" style={{ marginLeft: 6 }}>AI</span>}</td>
                  <td><Labels labels={a.labels} /></td>
                  <td className="mono">{a.src_ip}</td>
                  <td className="num">{a.flow_count}</td>
                  <td className="num">{a.blocked_count}</td>
                  <td className="muted">{ago(a.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
        {data && <Pager total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />}
      </Card>
      {alertId && <AlertDrawer id={Number(alertId)} onClose={() => nav("/alerts")} onChange={reload} />}
    </>
  );
}

function AlertDrawer({ id, onClose, onChange }: { id: number; onClose: () => void; onChange: () => void }) {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: a, error, reload, setData } = useApi<Alert>(`/alerts/${id}`, { poll: 8000 });
  const { data: flows } = useApi<Page<FlowSummary>>(`/flows?alert_id=${id}&hours=720&limit=25`);

  const update = async (status: string) => {
    const r = await run(() => api<Alert>(`/alerts/${id}`, { method: "PATCH", json: { status } }), `Alert marked ${human(status)}`);
    if (r) { setData(r); onChange(); }
  };
  const triage = async () => {
    const r = await run(() => api<Alert>(`/alerts/${id}/triage`, { method: "POST" }), "Triage complete");
    if (r) { setData(r); onChange(); }
  };
  const narrate = async () => {
    if (await run(() => api(`/alerts/${id}/narrate`, { method: "POST" }), "Incident narrative ready")) reload();
  };

  return (
    <Drawer onClose={onClose} title={a ? a.title : `Alert #${id}`}
      sub={a && <span className="row"><Badge kind={a.severity} dot /><Badge kind={a.status} /><span>#{a.id} · first seen {dateTime(a.first_seen)}</span></span>}>
      {error && <ErrorBox error={error} />}
      {!a ? <Loading /> : (
        <>
          <div className={`callout ${a.summary_source === "llm" ? "ai" : ""}`}>
            <div className="row" style={{ marginBottom: 6 }}>
              <h3>Summary</h3>
              <Badge kind={a.summary_source}>{a.summary_source === "llm" ? "Claude" : a.summary_source}</Badge>
              {a.tier3_pending && <span className="row faint"><span className="spinner" /> Tier 3 triage queued</span>}
            </div>
            {a.summary}
          </div>
          {a.recommended_actions.length > 0 && (
            <div><h3 style={{ marginBottom: 8 }}>Recommended actions</h3>
              <ol className="list-plain">{a.recommended_actions.map((x) => <li key={x}>{x}</li>)}</ol></div>
          )}
          <dl className="kv">
            <dt>Labels</dt><dd><Labels labels={a.labels} /></dd>
            <dt>Source → destination</dt><dd className="mono">{a.src_ip} → {a.dst_ip}</dd>
            <dt>Flows / blocked</dt><dd>{a.flow_count} / {a.blocked_count}</dd>
            <dt>Peak anomaly</dt><dd className="mono">{a.max_score.toFixed(2)}</dd>
            <dt>Node</dt><dd className="mono">{a.node_id}</dd>
            <dt>Rule draft</dt><dd>{a.draft_id ? <Link to={`/approvals/${a.draft_id}`}>Review proposed rule →</Link> : <span className="faint">none yet</span>}</dd>
          </dl>
          <div className="row">
            {can("alerts:triage") && a.status !== "acknowledged" && a.status === "open" && <button onClick={() => update("acknowledged")} disabled={busy}>Acknowledge</button>}
            {can("alerts:triage") && a.status !== "resolved" && <button onClick={() => update("resolved")} disabled={busy}>Resolve</button>}
            {can("alerts:triage") && a.status !== "false_positive" && <button onClick={() => update("false_positive")} disabled={busy}>False positive</button>}
            {can("alerts:triage") && ["resolved", "false_positive"].includes(a.status) && <button onClick={() => update("open")} disabled={busy}>Reopen</button>}
          </div>
          {can("advisor:use") && (
            <div className="row">
              <button className="ai" onClick={triage} disabled={busy}>{a.draft_id ? "Re-run triage" : "Triage & draft rule"}</button>
              <button className="ai" onClick={narrate} disabled={busy}>Narrate incident</button>
            </div>
          )}
          {a.narrative && (
            <Card title={<div className="row"><h2>Incident narrative</h2><Badge kind={a.narrative.source}>{a.narrative.source === "llm" ? "Claude" : a.narrative.source}</Badge></div>}>
              <p style={{ marginTop: 0 }}>{a.narrative.narrative}</p>
              <ul className="timeline">{a.narrative.timeline.map((t, i) => <li key={i}>{t}</li>)}</ul>
            </Card>
          )}
          <div>
            <div className="row" style={{ marginBottom: 8 }}><h3>Evidence flows</h3><Link className="right" to={`/flows?alert_id=${id}`}>Open in explorer →</Link></div>
            <Card pad={false}>{flows ? <FlowTable items={flows.items} compact /> : <Loading />}</Card>
          </div>
        </>
      )}
    </Drawer>
  );
}
