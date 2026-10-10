import { useState } from "react";
import { Card, ErrorBox, Loading, PageHead, Pager } from "../components/ui";
import { ExportButton } from "../components/controls";
import { api, type AuditRow, type Page } from "../lib/api";
import { dateTime } from "../lib/format";
import { useAction, useApi } from "../lib/hooks";

const LIMIT = 100;

export function Audit() {
  const [offset, setOffset] = useState(0);
  const [prefix, setPrefix] = useState("");
  const { run, busy } = useAction();
  const [verify, setVerify] = useState<{ valid: boolean; entries?: number; error?: string } | null>(null);
  const qs = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
  if (prefix) qs.set("action", prefix);
  const { data, error } = useApi<Page<AuditRow>>(`/audit?${qs}`);

  return (
    <>
      <PageHead
        title="Audit trail"
        desc="Append-only, hash-chained record of every enforcement change, approval, bundle and sign-in. Any edit or deletion of a past entry breaks verification."
        actions={<><ExportButton path={`/audit/export.csv${prefix ? `?action=${encodeURIComponent(prefix)}` : ""}`} filename="audit.csv" /><button disabled={busy} onClick={async () => { const r = await run(() => api<{ valid: boolean; entries?: number; error?: string }>("/audit/verify")); if (r) setVerify(r); }}>Verify chain integrity</button></>}
      />
      {verify && (
        <div className={`callout ${verify.valid ? "" : "danger"}`} style={verify.valid ? { borderLeftColor: "var(--allow)" } : undefined}>
          {verify.valid ? <>✓ Chain intact — {verify.entries?.toLocaleString()} entries verified from genesis.</> : <>✗ Chain verification FAILED: {verify.error}</>}
        </div>
      )}
      <Card pad={false} title={
        <select value={prefix} onChange={(e) => { setPrefix(e.target.value); setOffset(0); }} aria-label="Action filter">
          <option value="">all actions</option>
          {["draft.", "rule.", "bundle.", "node.", "user.", "auth.", "alert."].map((p) => <option key={p} value={p}>{p}*</option>)}
        </select>
      }>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : (
          <div className="table-wrap"><table>
            <thead><tr><th className="num">#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>Hash</th></tr></thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.seq}>
                  <td className="num">{a.seq}</td>
                  <td className="mono muted">{dateTime(a.ts)}</td>
                  <td>{a.actor}</td>
                  <td className="mono">{a.action}</td>
                  <td className="mono">{a.target}</td>
                  <td className="mono faint truncate" style={{ maxWidth: 360 }} title={JSON.stringify(a.detail)}>{Object.entries(a.detail).filter(([, v]) => v !== null && v !== "").map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join(" ")}</td>
                  <td className="mono faint">{a.hash.slice(0, 10)}…</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
        {data && <Pager total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />}
      </Card>
    </>
  );
}
