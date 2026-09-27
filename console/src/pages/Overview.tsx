import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { BarList, VerdictTimeline } from "../components/charts";
import { Badge, Card, ErrorBox, Kpi, Labels, Loading, PageHead } from "../components/ui";
import type { Alert, Dashboard, Page } from "../lib/api";
import { ago, num, pct } from "../lib/format";
import { useApi } from "../lib/hooks";

const WINDOWS = [1, 6, 24, 168];

export function Overview() {
  const [hours, setHours] = useState(24);
  const nav = useNavigate();
  const { data: d, error } = useApi<Dashboard>(`/dashboard?hours=${hours}`, { poll: 10000 });
  const { data: alerts } = useApi<Page<Alert>>("/alerts?status=open&limit=6", { poll: 10000 });

  if (error) return <ErrorBox error={error} />;
  if (!d) return <Loading />;
  const alertCount = Object.values(d.open_alerts).reduce((a, b) => a + b, 0);
  const flagged = (d.by_action.alert ?? 0) + d.enforced_blocks;

  return (
    <>
      <PageHead
        title="Overview"
        desc="Traffic verdicts, detections and policy health across the fleet."
        actions={
          <div className="segmented" role="group" aria-label="Time window">
            {WINDOWS.map((h) => (
              <button key={h} className={h === hours ? "on" : ""} onClick={() => setHours(h)}>{h < 48 ? `${h}h` : `${h / 24}d`}</button>
            ))}
          </div>
        }
      />
      {!d.tier1_trained && (
        <div className="callout warn">
          Tier 1 is still learning the traffic baseline. Anomaly scores are low-confidence until warm-up completes.
        </div>
      )}
      <div className="grid kpis">
        <Kpi label="Flows analysed" value={num(d.total_flows)} sub={`last ${hours}h`} />
        <Kpi label="Blocked (enforced)" value={num(d.enforced_blocks)} tone="block"
          sub={d.total_flows ? `${pct(d.enforced_blocks / d.total_flows, 2)} of traffic` : "—"} />
        <Kpi label="Alerted" value={num(d.by_action.alert ?? 0)} tone="alert" sub={`${num(flagged)} flagged total`} />
        <Kpi label="Open alerts" value={alertCount}
          sub={<span className="row" style={{ gap: 4 }}>{(["critical", "high", "medium", "low"] as const).filter((s) => d.open_alerts[s]).map((s) => <Badge key={s} kind={s}>{d.open_alerts[s]} {s}</Badge>)}</span>} />
        <Kpi label="Awaiting approval" value={d.pending_drafts} tone={d.pending_drafts ? "ai" : ""}
          sub={<Link to="/approvals">Review drafts →</Link>} />
        <Kpi label="Active rules" value={d.active_rules} sub={`bundle v${d.bundle_version}`} />
      </div>

      <div className="grid two">
        <Card title="Verdicts over time">
          <VerdictTimeline points={d.timeline} bucket={d.bucket_seconds} />
        </Card>
        <Card title="Detections by label">
          <BarList items={Object.entries(d.labels).map(([label, value]) => ({ label, value }))}
            onClick={(l) => nav(`/flows?label=${l}`)} />
        </Card>
      </div>

      <div className="grid two">
        <Card title="Open alerts" actions={<Link to="/alerts">All alerts →</Link>} pad={false}>
          {alerts?.items.length ? (
            <div className="table-wrap"><table>
              <thead><tr><th>Severity</th><th>Alert</th><th>Labels</th><th className="num">Flows</th><th>Last seen</th></tr></thead>
              <tbody>
                {alerts.items.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => nav(`/alerts/${a.id}`)}>
                    <td><Badge kind={a.severity} dot /></td>
                    <td className="truncate">{a.title}</td>
                    <td><Labels labels={a.labels} /></td>
                    <td className="num">{a.flow_count}</td>
                    <td className="muted">{ago(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          ) : <div className="empty">No open alerts. Quiet is good.</div>}
        </Card>
        <Card title="Top flagged sources">
          <BarList color="var(--block)" items={d.top_sources.map((s) => ({ label: s.ip, value: s.count }))}
            onClick={(ip) => nav(`/flows?q=${ip}`)} />
        </Card>
      </div>
    </>
  );
}
