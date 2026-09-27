import { useState } from "react";
import { Badge, Card, ErrorBox, Loading, Meter, Modal, PageHead } from "../components/ui";
import { api, type Bundle } from "../lib/api";
import { ago } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

export function Bundles() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data, error, reload } = useApi<Bundle[]>("/bundles", { poll: 10000 });
  const [rollback, setRollback] = useState<Bundle | null>(null);
  const [reason, setReason] = useState("");

  return (
    <>
      <PageHead
        title="Bundles & rollout"
        desc="Each rule change produces an Ed25519-signed policy bundle. Nodes verify the signature themselves and receive new bundles in stages (5% → 25% → 100%), with automatic rollback if canaries block materially more traffic."
        actions={can("rules:approve") && <button disabled={busy} onClick={async () => { if (await run(() => api("/bundles/publish", { method: "POST" }), "Bundle published")) reload(); }}>Publish now</button>}
      />
      <Card pad={false}>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Version</th><th>Status</th><th style={{ width: 180 }}>Rollout</th><th className="num">Rules</th><th>Note</th><th>Published</th><th>Signing key</th><th /></tr></thead>
            <tbody>
              {data.map((b) => (
                <tr key={b.version}>
                  <td className="mono">v{b.version}</td>
                  <td><Badge kind={b.status} dot /></td>
                  <td>{b.status === "rolling_out" || b.status === "active" ? <div className="row" style={{ flexWrap: "nowrap" }}><div style={{ flex: 1 }}><Meter value={b.rollout_percent / 100} /></div><span className="mono">{b.rollout_percent}%</span></div> : <span className="faint">—</span>}</td>
                  <td className="num">{b.rule_count}</td>
                  <td className="truncate muted" style={{ maxWidth: 260 }}>{b.note}</td>
                  <td className="muted">{ago(b.created_at)} · {b.created_by}</td>
                  <td className="mono faint">{b.key_id}</td>
                  <td className="row" style={{ flexWrap: "nowrap" }}>
                    {can("rules:approve") && b.status === "rolling_out" && <button className="small" disabled={busy} onClick={async () => { if (await run(() => api(`/bundles/${b.version}/advance`, { method: "POST" }), "Rollout advanced")) reload(); }}>Advance</button>}
                    {can("rules:approve") && ["rolling_out", "active"].includes(b.status) && b.version > 1 && <button className="small danger" disabled={busy} onClick={() => { setReason(""); setRollback(b); }}>Roll back</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      {rollback && (
        <Modal title={`Roll back v${rollback.version}?`} onClose={() => setRollback(null)} footer={<>
          <button onClick={() => setRollback(null)}>Cancel</button>
          <button className="danger" disabled={!reason.trim() || busy} onClick={async () => {
            const r = await run(() => api<{ new_version: number }>(`/bundles/${rollback.version}/rollback`, { method: "POST", json: { reason } }));
            if (r) { setRollback(null); reload(); }
          }}>Roll back</button></>}>
          <p style={{ margin: 0 }}>The rule set of the previous good bundle is restored and published as a new version to all nodes immediately.</p>
          <label className="field">Reason (audited)<textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        </Modal>
      )}
    </>
  );
}
