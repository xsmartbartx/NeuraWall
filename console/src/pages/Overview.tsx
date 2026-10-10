import { useState, type CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import { BarList, VerdictTimeline } from "../components/charts";
import { Badge, Card, ErrorBox, Kpi, Labels, Loading, PageHead, Meter } from "../components/ui";
import type { Alert, Dashboard, Page } from "../lib/api";
import { ago, num, pct } from "../lib/format";
import { useApi, useAuth } from "../lib/hooks";

const WINDOWS = [1, 6, 24, 168];

function healthScore(d: Dashboard): number {
  let score = 100;
  if (d.nodes.total === 0) score -= 45;
  else score -= Math.round((1 - d.nodes.online / d.nodes.total) * 30);
  const alerts = Object.values(d.open_alerts).reduce((sum, n) => sum + n, 0);
  score -= Math.min(30, alerts * 3);
  score -= Math.min(20, d.pending_drafts * 4);
  if (!d.tier1_trained) score -= 10;
  if (d.advisor_mode === "degraded") score -= 5;
  if (d.advisor_mode === "offline") score -= 8;
  return Math.max(0, Math.min(100, score));
}

function scoreTone(score: number) {
  return score >= 90 ? "allow" : score >= 70 ? "alert" : "block";
}

export function Overview() {
  const [hours, setHours] = useState(24);
  const nav = useNavigate();
  const { me } = useAuth();
  const { data: d, error } = useApi<Dashboard>(`/dashboard?hours=${hours}`, { poll: 10000 });
  const { data: alerts } = useApi<Page<Alert>>("/alerts?status=open&limit=6", { poll: 10000 });
  const { data: billing } = useApi<{
    plan: { name: string; nodes_limit: number | null; retention_days: number | null; llm_advisor_allowed: boolean };
    usage: { nodes: number; retention_days: number };
  }>("/billing");

  if (error) return <ErrorBox error={error} />;
  if (!d) return <Loading />;

  const alertCount = Object.values(d.open_alerts).reduce((a, b) => a + b, 0);
  const score = healthScore(d);
  const tone = scoreTone(score);
  const nodeCapacity = billing?.plan.nodes_limit ? billing.usage.nodes / billing.plan.nodes_limit : 0;
  const firstName = me?.name?.trim() ? me.name.trim().split(/\s+/)[0] : "there";
  const healthText = score >= 90 ? "Healthy" : score >= 70 ? "Needs attention" : "Action required";

  return (
    <>
      <PageHead
        title={`Good morning, ${firstName}`}
        desc="Customer command center for security posture, service health, policy recommendations and subscription usage."
        actions={
          <div className="segmented" role="group" aria-label="Time window">
            {WINDOWS.map((h) => (
              <button key={h} className={h === hours ? "on" : ""} onClick={() => setHours(h)}>
                {h < 48 ? `${h}h` : `${h / 24}d`}
              </button>
            ))}
          </div>
        }
      />

      {!d.tier1_trained && (
        <div className="callout warn">
          Tier 1 is still learning the traffic baseline. Anomaly scores remain low-confidence until warm-up completes.
        </div>
      )}

      <section className="customer-hero">
        <div className="customer-health">
          <div className="health-ring" style={{ "--score": score } as CSSProperties} aria-label={`Security posture ${score} out of 100`}>
            <div><strong>{score}</strong><span>/100</span></div>
          </div>
          <div>
            <div className="eyebrow">Security posture</div>
            <h2 className={`health-${tone}`}>{healthText}</h2>
            <p className="muted customer-hero-copy">
              {alertCount === 0 && d.nodes.total === d.nodes.online
                ? "No open alerts and the connected fleet is fully online."
                : `${alertCount} open alert${alertCount === 1 ? "" : "s"} and ${d.nodes.total - d.nodes.online} fleet issue${d.nodes.total - d.nodes.online === 1 ? "" : "s"} currently affect posture.`}
            </p>
          </div>
        </div>
        <div className="customer-actions">
          {alertCount > 0 && <Link className="btn primary-link" to="/alerts">Review alerts</Link>}
          {d.pending_drafts > 0 && <Link className="btn" to="/approvals">Review AI recommendations</Link>}
          {d.nodes.total === 0 && <Link className="btn" to="/fleet">Connect first node</Link>}
          {alertCount === 0 && d.pending_drafts === 0 && d.nodes.total > 0 && <Link className="btn" to="/flows">Explore traffic</Link>}
        </div>
      </section>

      <div className="grid customer-kpis">
        <Kpi label="Protection coverage" value={d.nodes.total ? pct(d.nodes.online / d.nodes.total, 0) : "0%"} sub={`${d.nodes.online}/${d.nodes.total} nodes online`} />
        <Kpi label="Threats blocked" value={num(d.enforced_blocks)} tone="block" sub={d.total_flows ? `${pct(d.enforced_blocks / d.total_flows, 2)} of analysed traffic` : "No analysed traffic"} />
        <Kpi label="Open alerts" value={alertCount} tone={alertCount ? "alert" : ""} sub={alertCount ? "Needs review" : "No active incident backlog"} />
        <Kpi label="Active policy" value={num(d.active_rules)} sub={`bundle v${d.bundle_version}`} />
        <Kpi label="AI advisor" value={d.advisor_mode === "online" ? "Online" : d.advisor_mode === "degraded" ? "Degraded" : "Offline"} tone="ai"
          sub={`Tier 3 · ${billing?.plan.llm_advisor_allowed ? "plan enabled" : "offline advisor"}`} />
      </div>

      <div className="grid customer-main">
        <div className="stack">
          <Card title="Protection activity" actions={<Link to="/flows">View traffic →</Link>}>
            <VerdictTimeline points={d.timeline} bucket={d.bucket_seconds} />
          </Card>
          <Card title="Open alerts" actions={<Link to="/alerts">All alerts →</Link>} pad={false}>
            {alerts?.items.length ? (
              <div className="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Alert</th><th>Source</th><th className="num">Flows</th><th>Last seen</th></tr></thead>
                <tbody>
                  {alerts.items.map((a) => (
                    <tr key={a.id} className="clickable" onClick={() => nav(`/alerts/${a.id}`)}>
                      <td><Badge kind={a.severity} dot /></td>
                      <td className="truncate">{a.title}</td>
                      <td className="mono">{a.src_ip}</td>
                      <td className="num">{a.flow_count}</td>
                      <td className="muted">{ago(a.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            ) : <div className="empty">No open alerts. Quiet is good.</div>}
          </Card>
        </div>

        <div className="stack">
          <Card title="Your plan">
            {billing ? (
              <>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <b>{billing.plan.name}</b><Link to="/billing">Manage →</Link>
                </div>
                <div className="stack" style={{ marginTop: 12 }}>
                  <div>
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <span className="muted">Nodes</span>
                      <span className="mono">{billing.usage.nodes} / {billing.plan.nodes_limit ?? "∞"}</span>
                    </div>
                    <Meter value={nodeCapacity} warn={nodeCapacity >= 1} />
                  </div>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <span className="muted">Retention</span>
                    <span className="mono">{billing.usage.retention_days}d</span>
                  </div>
                </div>
              </>
            ) : <Loading what="Loading plan" />}
          </Card>

          <Card title="Next best actions">
            <div className="next-actions">
              {d.nodes.total === 0 && <Link to="/fleet" className="next-action"><span className="next-icon">01</span><span><b>Connect a node</b><small>Start sending traffic to NeuraWall.</small></span></Link>}
              {d.nodes.total > 0 && d.nodes.online < d.nodes.total && <Link to="/fleet" className="next-action"><span className="next-icon">01</span><span><b>Restore fleet coverage</b><small>{d.nodes.total - d.nodes.online} node(s) are offline.</small></span></Link>}
              {d.pending_drafts > 0 && <Link to="/approvals" className="next-action"><span className="next-icon">02</span><span><b>Review AI recommendations</b><small>{d.pending_drafts} policy change(s) awaiting review.</small></span></Link>}
              {!d.tier1_trained && <Link to="/flows" className="next-action"><span className="next-icon">03</span><span><b>Finish baseline learning</b><small>Keep normal traffic flowing while Tier 1 warms up.</small></span></Link>}
              {d.nodes.total > 0 && d.nodes.online === d.nodes.total && d.pending_drafts === 0 && d.tier1_trained && <Link to="/rules" className="next-action"><span className="next-icon">03</span><span><b>Review policy hygiene</b><small>Check active rules and reduce unnecessary exposure.</small></span></Link>}
            </div>
          </Card>

          <Card title="Threat mix">
            <BarList items={Object.entries(d.labels).map(([label, value]) => ({ label, value }))} onClick={(l) => nav(`/flows?label=${l}`)} />
          </Card>
        </div>
      </div>
    </>
  );
}
