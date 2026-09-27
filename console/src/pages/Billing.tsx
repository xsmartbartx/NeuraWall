import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Badge, Card, ErrorBox, Loading, Meter, PageHead } from "../components/ui";
import { api } from "../lib/api";
import { dateTime } from "../lib/format";
import { useAction, useApi, useAuth, useToast } from "../lib/hooks";

interface PlanInfo {
  id: string; name: string; nodes_limit: number | null; retention_days: number | null;
  llm_advisor_allowed: boolean; support: string; self_serve: boolean;
  price_cents_month: number; price_cents_year: number;
  purchasable?: { month: boolean; year: boolean };
}

interface BillingStatus {
  plan: PlanInfo;
  source: "stripe" | "licence";
  subscription: { status: string; current_period_end: number | null; manageable: boolean } | null;
  usage: { nodes: number; retention_days: number };
  self_serve: boolean;
  plans: PlanInfo[];
}

const usd = (cents: number) => `$${(cents / 100).toLocaleString("en-US")}`;
const SALES = "mailto:hello@onenexora.com?subject=";

export function Billing() {
  const { can } = useAuth();
  const toast = useToast();
  const { run, busy } = useAction();
  const [params, setParams] = useSearchParams();
  const [interval, setInterval] = useState<"month" | "year">("month");
  const { data: b, error, reload } = useApi<BillingStatus>("/billing");
  const admin = can("settings:manage");

  useEffect(() => {
    if (params.get("checkout") === "success") {
      toast("Payment received — your plan updates as soon as Stripe confirms it.");
      setParams({}, { replace: true });
      const t = window.setTimeout(reload, 4000);
      return () => window.clearTimeout(t);
    }
  }, [params, setParams, toast, reload]);

  const checkout = async (plan: string) => {
    const r = await run(() => api<{ checkout_url: string }>("/billing/checkout", { method: "POST", json: { plan, interval } }));
    if (r) window.location.assign(r.checkout_url);
  };
  const portal = async () => {
    const r = await run(() => api<{ portal_url: string }>("/billing/portal", { method: "POST" }));
    if (r) window.location.assign(r.portal_url);
  };

  if (error) return <ErrorBox error={error} />;
  if (!b) return <Loading />;
  const { plan, usage } = b;
  const nodeShare = plan.nodes_limit ? usage.nodes / plan.nodes_limit : 0;

  return (
    <>
      <PageHead title="Billing" desc="Your NeuraWall plan, what it includes and how much of it you use. Payments are handled by Stripe." />
      <div className="grid halves">
        <Card title={<div className="row"><h2>Current plan</h2><Badge kind="active">{plan.name}</Badge>
          <span className="faint">{b.source === "stripe" ? "via Stripe" : "licence"}</span></div>}>
          <dl className="kv">
            <dt>Enforcement nodes</dt>
            <dd>
              <div className="row" style={{ flexWrap: "nowrap" }}>
                <div style={{ flex: 1, minWidth: 120 }}><Meter value={nodeShare} warn={nodeShare >= 1} /></div>
                <span className="mono">{usage.nodes} / {plan.nodes_limit ?? "∞"}</span>
              </div>
            </dd>
            <dt>Flow retention</dt><dd className="mono">{usage.retention_days} days</dd>
            <dt>Claude AI advisor</dt><dd>{plan.llm_advisor_allowed ? "Included" : "Offline advisor only"}</dd>
            <dt>Support</dt><dd>{plan.support}</dd>
            {b.subscription && <>
              <dt>Subscription</dt><dd><Badge kind={b.subscription.status === "active" ? "active" : "revoked"}>{b.subscription.status}</Badge></dd>
              <dt>Renews</dt><dd>{dateTime(b.subscription.current_period_end)}</dd>
            </>}
          </dl>
          {admin && b.subscription?.manageable && (
            <div className="row" style={{ marginTop: 14 }}>
              <button disabled={busy} onClick={portal}>Manage subscription</button>
              <span className="faint">Change plan, update your card, download invoices or cancel.</span>
            </div>
          )}
        </Card>
        <Card title="How plans work">
          <ul className="list-plain">
            <li>Node limits apply when you enroll a node; existing nodes keep enforcing if you downgrade.</li>
            <li>Flow retention follows your plan (used by the rule simulator and investigations).</li>
            <li>A failed renewal keeps your plan while Stripe retries the payment.</li>
            <li>Yearly billing gives two months free.</li>
          </ul>
          {!b.self_serve && <div className="callout" style={{ marginTop: 12 }}>Self-serve checkout isn't enabled on this installation. Contact <a href={`${SALES}NeuraWall%20licence`}>sales</a> for a licence.</div>}
          {!admin && <div className="callout" style={{ marginTop: 12 }}>Only administrators can change the plan.</div>}
        </Card>
      </div>

      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Plans</h2>
        <div className="segmented" role="group" aria-label="Billing interval">
          <button className={interval === "month" ? "on" : ""} onClick={() => setInterval("month")}>Monthly</button>
          <button className={interval === "year" ? "on" : ""} onClick={() => setInterval("year")}>Yearly — 2 months free</button>
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))" }}>
        {b.plans.map((p) => {
          const current = p.id === plan.id;
          const price = p.id === "enterprise_dedicated" ? "$5,000–15,000"
            : interval === "year" && p.price_cents_year ? usd(p.price_cents_year) : usd(p.price_cents_month);
          const per = p.id === "enterprise_dedicated" || interval === "month" || !p.price_cents_year ? "/ month" : "/ year";
          const canBuy = admin && p.purchasable?.[interval] && !current;
          return (
            <div key={p.id} className="card kpi" style={{ gap: 10, borderColor: current ? "var(--accent)" : undefined }}>
              <div className="row"><b>{p.name}</b>{current && <Badge kind="active">current</Badge>}</div>
              <div><span className="value" style={{ fontSize: 22 }}>{price}</span> <span className="faint">{per}</span></div>
              <ul className="list-plain" style={{ fontSize: 12.5 }}>
                <li>{p.nodes_limit === null ? "Custom" : p.nodes_limit} enforcement node{p.nodes_limit === 1 ? "" : "s"}</li>
                <li>{p.retention_days === null ? "Custom" : `${p.retention_days}-day`} retention</li>
                <li>{p.llm_advisor_allowed ? "Claude AI advisor" : "Offline AI advisor"}</li>
                <li>{p.support} support</li>
              </ul>
              {current ? <span className="faint">Your plan</span>
                : canBuy ? <button className="primary" disabled={busy} onClick={() => checkout(p.id)}>Upgrade to {p.name}</button>
                : p.price_cents_month > 0 ? <a className="btn" href={`${SALES}${encodeURIComponent(`NeuraWall ${p.name}`)}`}>Contact sales</a>
                : null}
            </div>
          );
        })}
      </div>
      <p className="faint" style={{ margin: 0 }}>Professional services — architecture, deployment and training — at $125 per hour.</p>
    </>
  );
}
