import { useEffect, type ReactNode } from "react";
import { human } from "../lib/format";

export function Badge({ kind, children, dot }: { kind: string; children?: ReactNode; dot?: boolean }) {
  return <span className={`badge c-${kind} ${dot ? "dot" : ""}`}>{children ?? human(kind)}</span>;
}

export function Labels({ labels }: { labels: string[] }) {
  if (!labels.length) return <span className="faint">—</span>;
  return <span className="row" style={{ gap: 4 }}>{labels.map((l) => <span key={l} className="label-chip">{l}</span>)}</span>;
}

export function Card({ title, actions, children, pad = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; pad?: boolean }) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="card-head">
          {typeof title === "string" ? <h2>{title}</h2> : title}
          <span className="spacer" />
          {actions}
        </div>
      )}
      {pad ? <div className="card-body">{children}</div> : children}
    </section>
  );
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className={`card kpi ${tone ?? ""}`}>
      <span className="label">{label}</span>
      <span className="value">{value}</span>
      {sub && <span className="sub">{sub}</span>}
    </div>
  );
}

export function PageHead({ title, desc, actions }: { title: string; desc?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div><h1>{title}</h1>{desc && <p>{desc}</p>}</div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="empty"><span className="spinner" /> <span style={{ marginLeft: 8 }}>{what}…</span></div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorBox({ error }: { error: string }) {
  return <div className="callout danger">{error}</div>;
}

export function Meter({ value, warn }: { value: number; warn?: boolean }) {
  return <div className={`meter ${warn ? "warn" : ""}`}><span style={{ width: `${Math.min(100, Math.max(1, value * 100))}%` }} /></div>;
}

export function Drawer({ onClose, title, sub, children }: { onClose: () => void; title: ReactNode; sub?: ReactNode; children: ReactNode }) {
  useEscape(onClose);
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <div className="drawer-head">
          <div style={{ flex: 1, minWidth: 0 }}><h2>{title}</h2>{sub && <div className="muted" style={{ marginTop: 4 }}>{sub}</div>}</div>
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

export function Modal({ title, onClose, children, footer }: { title: string; onClose: () => void; children: ReactNode; footer: ReactNode }) {
  useEscape(onClose);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="card-head"><h2>{title}</h2></div>
        <div className="card-body">{children}</div>
        <div className="modal-foot">{footer}</div>
      </div>
    </div>
  );
}

function useEscape(fn: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && fn();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [fn]);
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  if (total <= limit) return null;
  return (
    <div className="pager">
      <span>{offset + 1}–{Math.min(total, offset + limit)} of {total.toLocaleString()}</span>
      <button className="small" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Prev</button>
      <button className="small" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
    </div>
  );
}

export function Copy({ text }: { text: string }) {
  return (
    <button className="small" onClick={() => navigator.clipboard?.writeText(text)} title="Copy to clipboard">Copy</button>
  );
}
