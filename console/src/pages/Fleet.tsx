import { useState } from "react";
import { Badge, Card, Copy, Empty, ErrorBox, Loading, Modal, PageHead } from "../components/ui";
import { api, type NodeRow } from "../lib/api";
import { ago } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

export function Fleet() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data, error, reload } = useApi<NodeRow[]>("/nodes", { poll: 10000 });
  const [token, setToken] = useState<{ token: string; control_plane_url: string; expires_in: number } | null>(null);
  const [revoking, setRevoking] = useState<NodeRow | null>(null);

  const origin = token?.control_plane_url ?? window.location.origin;
  const install = token && [
    `pip install neurawall   # or use the ghcr.io/neurawall/neurawall image`,
    `sudo neurawall agent enroll --url ${origin} --state-dir /var/lib/neurawall-agent --token ${token.token}`,
    `sudo neurawall agent run --config /etc/neurawall/agent.yaml`,
  ].join("\n");

  return (
    <>
      <PageHead
        title="Fleet"
        desc="Enforcement nodes. Each node pins the bundle-signing key at enrollment, verifies every bundle independently and keeps enforcing its last-known-good policy if the control plane is unreachable."
        actions={can("fleet:manage") && (
          <button className="primary" disabled={busy} onClick={async () => {
            const r = await run(() => api<{ token: string; control_plane_url: string; expires_in: number }>("/nodes/enrollment-tokens", { method: "POST", json: { ttl_seconds: 3600 } }));
            if (r) setToken(r);
          }}>Enroll a node</button>
        )}
      />
      <Card pad={false}>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : !data.length ? (
          <Empty>No nodes enrolled yet. Enroll a node to start enforcing policy at the edge.</Empty>
        ) : (
          <div className="table-wrap"><table>
            <thead><tr><th>Node</th><th>Status</th><th>Bundle</th><th>Datapath</th><th className="num">Flows sent</th><th className="num">Active blocks</th><th>Last seen</th><th>Agent</th><th /></tr></thead>
            <tbody>
              {data.map((n) => (
                <tr key={n.id}>
                  <td><div>{n.name}</div><div className="mono faint" style={{ fontSize: 11.5 }}>{n.id} · {n.hostname}</div></td>
                  <td><Badge kind={n.status} dot /></td>
                  <td><span className="mono">v{n.applied_version}</span> {!n.up_to_date && n.status !== "revoked" && <Badge kind="rolling_out">behind</Badge>}</td>
                  <td className="mono">{n.backend}{n.stats.datapath_error ? <span title={String(n.stats.datapath_error)} style={{ color: "var(--block)" }}> ⚠</span> : null}</td>
                  <td className="num">{Number(n.stats.flows_sent ?? 0).toLocaleString()}</td>
                  <td className="num">{Number(n.stats.active_blocks ?? 0).toLocaleString()}</td>
                  <td className="muted">{ago(n.last_seen)}</td>
                  <td className="mono faint">{n.agent_version}</td>
                  <td>{can("fleet:manage") && n.status !== "revoked" && <button className="small danger" onClick={() => setRevoking(n)}>Revoke</button>}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      {token && install && (
        <Modal title="Enroll a node" onClose={() => setToken(null)} footer={<button className="primary" onClick={() => { setToken(null); reload(); }}>Done</button>}>
          <p style={{ margin: 0 }}>This single-use token expires in {Math.round(token.expires_in / 60)} minutes. Run on the node:</p>
          <pre className="code">{install}</pre>
          <div className="row"><Copy text={install} /><span className="faint">Token shown once. It is stored only as a hash.</span></div>
          <div className="callout">Use <code>backend: nftables</code> in agent.yaml to enforce on Linux (needs CAP_NET_ADMIN), or <code>dry-run</code> to evaluate without touching the host. See <code>docs/deployment.md</code>.</div>
        </Modal>
      )}
      {revoking && (
        <Modal title={`Revoke ${revoking.name}?`} onClose={() => setRevoking(null)} footer={<>
          <button onClick={() => setRevoking(null)}>Cancel</button>
          <button className="danger" disabled={busy} onClick={async () => {
            if (await run(() => api(`/nodes/${revoking.id}/revoke`, { method: "POST" }), "Node revoked")) { setRevoking(null); reload(); }
          }}>Revoke credentials</button></>}>
          <p style={{ margin: 0 }}>The node's API key stops working immediately. It keeps enforcing its last-known-good bundle until re-enrolled or stopped.</p>
        </Modal>
      )}
    </>
  );
}
