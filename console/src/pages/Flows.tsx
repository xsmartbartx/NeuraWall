import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge, Card, Drawer, Empty, ErrorBox, Labels, Loading, PageHead, Pager } from "../components/ui";
import { ExportButton } from "../components/controls";
import { api, type FlowDetail, type FlowSummary, type Page } from "../lib/api";
import { bytes, dateTime, human } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

const LIMIT = 100;

export function FlowTable({ items, compact, onSelect, selected }: {
  items: FlowSummary[]; compact?: boolean; onSelect?: (id: string) => void; selected?: string | null;
}) {
  if (!items.length) return <Empty>No flows match.</Empty>;
  return (
    <div className="table-wrap"><table>
      <thead><tr>
        <th>Time</th><th>Verdict</th><th>Source</th><th>Destination</th>{!compact && <th>Host</th>}
        <th>Labels</th><th className="num">Anomaly</th>{!compact && <th className="num">Bytes</th>}<th>Rule</th>
      </tr></thead>
      <tbody>
        {items.map((f) => (
          <tr key={f.flow_id} className={`${onSelect ? "clickable" : ""} ${selected === f.flow_id ? "selected" : ""}`}
            onClick={() => onSelect?.(f.flow_id)}>
            <td className="mono muted">{dateTime(f.ts)}</td>
            <td><Badge kind={f.enforced ? f.action : f.action === "allow" ? "allow" : "alert"}>{human(f.action)}{f.enforced ? "" : f.action !== "allow" && f.action !== "alert" ? " (alert-only)" : ""}</Badge></td>
            <td className="mono">{f.src_ip}</td>
            <td className="mono">{f.dst_ip}:{f.dst_port}/{f.protocol}</td>
            {!compact && <td className="truncate mono" style={{ maxWidth: 220 }}>{f.host ?? "—"}</td>}
            <td><Labels labels={f.labels} /></td>
            <td className="num">{f.anomaly_score?.toFixed(2) ?? "—"}</td>
            {!compact && <td className="num">{bytes(f.bytes)}</td>}
            <td className="mono">{f.rule_id ?? <span className="faint">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table></div>
  );
}

export function Flows() {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [selected, setSelected] = useState<string | null>(null);
  const offset = Number(params.get("offset") ?? 0);
  const qs = new URLSearchParams(params);
  qs.set("limit", String(LIMIT));
  if (!qs.get("hours")) qs.set("hours", "24");
  const { data, error } = useApi<Page<FlowSummary>>(`/flows?${qs}`, { poll: 15000 });
  const exportQs = new URLSearchParams(qs);
  exportQs.delete("limit");
  exportQs.delete("offset");

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    next.delete("offset");
    setParams(next);
  };
  const submit = (e: FormEvent) => { e.preventDefault(); set("q", q.trim()); };

  return (
    <>
      <PageHead title="Flow explorer" desc="Every analysed flow with its Tier 1 score, Tier 2 labels and the policy verdict. Metadata only — payloads are never stored."
        actions={<ExportButton path={`/flows/export.csv?${exportQs}`} filename="flows.csv" />} />
      <Card pad={false} title={
        <form className="row" onSubmit={submit} style={{ flex: 1 }}>
          <input placeholder="IP, host or flow id" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 240 }} aria-label="Search" />
          <select value={params.get("action") ?? ""} onChange={(e) => set("action", e.target.value)} aria-label="Verdict">
            <option value="">any verdict</option><option value="blocked">blocked (enforced)</option>
            <option value="alert">alert</option><option value="allow">allow</option>
          </select>
          <select value={params.get("label") ?? ""} onChange={(e) => set("label", e.target.value)} aria-label="Label">
            <option value="">any label</option>
            {["sql_injection", "command_injection", "template_injection", "path_traversal", "xss", "dga", "dns_tunnel",
              "c2_beacon", "exfiltration", "tls_fingerprint_mismatch", "novel"].map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <select value={params.get("hours") ?? "24"} onChange={(e) => set("hours", e.target.value)} aria-label="Window">
            {[1, 6, 24, 168, 720].map((h) => <option key={h} value={h}>last {h < 48 ? `${h}h` : `${h / 24}d`}</option>)}
          </select>
          <button type="submit">Search</button>
          {params.get("alert_id") && <span className="badge c-info">alert #{params.get("alert_id")} <button className="ghost small" type="button" onClick={() => set("alert_id", "")}>✕</button></span>}
          {data && <span className="muted right">{data.total.toLocaleString()} flows</span>}
        </form>
      }>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> :
          <FlowTable items={data.items} onSelect={setSelected} selected={selected} />}
        {data && <Pager total={data.total} limit={LIMIT} offset={offset} onChange={(o) => {
          const next = new URLSearchParams(params); next.set("offset", String(o)); setParams(next);
        }} />}
      </Card>
      {selected && <FlowDrawer id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function FlowDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: f, error } = useApi<FlowDetail>(`/flows/${id}`);
  const [explain, setExplain] = useState<{ explanation: string; source: string } | null>(null);
  const l7 = f?.flow.l7 ?? null;

  return (
    <Drawer onClose={onClose} title={f ? `${f.src_ip} → ${f.dst_ip}:${f.dst_port}` : "Flow"} sub={<span className="mono">{id}</span>}>
      {error && <ErrorBox error={error} />}
      {!f ? <Loading /> : (
        <>
          <div className="callout">
            <div className="row" style={{ marginBottom: 6 }}>
              <h3>Verdict</h3>
              <Badge kind={f.verdict.enforced ? f.verdict.action : f.verdict.action === "allow" ? "allow" : "alert"}>{human(f.verdict.action)}</Badge>
              {f.verdict.enforced ? <Badge kind="block">enforced</Badge> : <span className="faint">not enforced</span>}
              {f.verdict.rule_id && <span className="mono">{f.verdict.rule_id}</span>}
            </div>
            <ul className="list-plain">{f.verdict.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
          </div>
          {can("advisor:use") && (
            <div>
              <button className="ai" disabled={busy} onClick={async () => {
                const r = await run(() => api<{ explanation: string; source: string }>(`/flows/${id}/explain`, { method: "POST" }));
                if (r) setExplain(r);
              }}>Explain this verdict</button>
              {explain && <div className="callout ai" style={{ marginTop: 10 }}>{explain.explanation}
                <div className="faint" style={{ marginTop: 6, fontSize: 12 }}>via {explain.source === "llm" ? "Claude" : explain.source}</div></div>}
            </div>
          )}
          <dl className="kv">
            <dt>Time</dt><dd>{dateTime(f.ts)}</dd>
            <dt>Node</dt><dd className="mono">{f.node_id}</dd>
            <dt>Protocol</dt><dd className="mono">{f.protocol} · {String(f.flow.direction)}</dd>
            <dt>Bytes out / in</dt><dd className="mono">{bytes(Number(f.flow.bytes_out))} / {bytes(Number(f.flow.bytes_in))}</dd>
            <dt>Packets out / in</dt><dd className="mono">{String(f.flow.packets_out)} / {String(f.flow.packets_in)}</dd>
            {f.alert_id && <><dt>Alert</dt><dd><Link to={`/alerts/${f.alert_id}`}>#{f.alert_id}</Link></dd></>}
          </dl>
          {l7 && Object.entries(l7).filter(([, v]) => v).map(([k, v]) => (
            <div key={k}><h3 style={{ marginBottom: 6 }}>{k.toUpperCase()} metadata</h3>
              <dl className="kv">{Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== null && x !== "" && !(Array.isArray(x) && !x.length)).map(([kk, vv]) => (
                <FragmentKV key={kk} k={kk} v={Array.isArray(vv) ? vv.join(", ") : String(vv)} />
              ))}</dl></div>
          ))}
          <Card title="Tier 1 — anomaly">
            {f.signals.anomaly ? (
              <div className="stack">
                <div className="row"><span className="mono" style={{ fontSize: 20 }}>{f.signals.anomaly.score.toFixed(3)}</span>
                  <span className="muted">score · confidence {f.signals.anomaly.confidence.toFixed(2)} · {f.signals.anomaly.model_version}</span></div>
                {f.signals.anomaly.top_features.length ? <Attributions items={f.signals.anomaly.top_features} /> : <span className="faint">No contributing features.</span>}
              </div>
            ) : <span className="faint">Not scored.</span>}
          </Card>
          <Card title="Tier 2 — classification">
            {f.signals.classifications.length ? f.signals.classifications.map((c, i) => (
              <div key={i} className="stack" style={{ marginBottom: 12 }}>
                <div className="row"><span className="label-chip">{c.label}</span><span className="mono">{(c.confidence * 100).toFixed(0)}%</span><span className="faint">{c.detector}</span></div>
                {c.attributions.length > 0 && <Attributions items={c.attributions} />}
              </div>
            )) : <span className="faint">Not escalated to Tier 2.</span>}
          </Card>
        </>
      )}
    </Drawer>
  );
}

function FragmentKV({ k, v }: { k: string; v: string }) {
  return <><dt>{human(k)}</dt><dd className="mono">{v}</dd></>;
}

function Attributions({ items }: { items: { feature: string; contribution: number; value?: string | number | null }[] }) {
  const max = Math.max(...items.map((a) => Math.abs(a.contribution)), 0.001);
  return (
    <div className="bar-list">
      {items.map((a) => (
        <div className="item" key={a.feature}>
          <span className="mono">{a.feature}{a.value !== undefined && a.value !== null && <span className="faint"> = {String(a.value)}</span>}</span>
          <span className="mono muted">{a.contribution.toFixed(2)}</span>
          <div className="track"><div className="fill" style={{ width: `${(Math.abs(a.contribution) / max) * 100}%`, background: a.contribution < 0 ? "var(--info)" : "var(--alert)" }} /></div>
        </div>
      ))}
    </div>
  );
}
