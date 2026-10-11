import { useEffect, useRef, type KeyboardEvent, type ReactNode } from "react";
import { human } from "../lib/format";

export function Badge({ kind, children, dot }: Readonly<{ kind: string; children?: ReactNode; dot?: boolean }>) {
  return <span className={`badge c-${kind} ${dot ? "dot" : ""}`}>{children ?? human(kind)}</span>;
}

export function Labels({ labels }: Readonly<{ labels: string[] }>) {
  if (!labels.length) return <span className="faint">—</span>;
  return <span className="row" style={{ gap: 4 }}>{labels.map((l) => <span key={l} className="label-chip">{l}</span>)}</span>;
}

export function Card({ title, actions, children, pad = true }: Readonly<{ title?: ReactNode; actions?: ReactNode; children: ReactNode; pad?: boolean }>) {
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

export function Kpi({ label, value, sub, tone }: Readonly<{ label: string; value: ReactNode; sub?: ReactNode; tone?: string }>) {
  return (
    <div className={`card kpi ${tone ?? ""}`}>
      <span className="label">{label}</span>
      <span className="value">{value}</span>
      {sub && <span className="sub">{sub}</span>}
    </div>
  );
}

export function PageHead({ title, desc, actions }: Readonly<{ title: string; desc?: ReactNode; actions?: ReactNode }>) {
  return (
    <div className="page-head">
      <div><h1>{title}</h1>{desc && <p>{desc}</p>}</div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Loading({ what = "Loading" }: Readonly<{ what?: string }>) {
  return <div className="empty"><span className="spinner" /> <span style={{ marginLeft: 8 }}>{what}…</span></div>;
}

export function Empty({ children }: Readonly<{ children: ReactNode }>) {
  return <div className="empty">{children}</div>;
}

export function Async<T>({ error, data, children }: Readonly<{
  error: string | null; data: T | null; children: (d: T) => ReactNode;
}>) {
  if (error) return <div className="card-body"><ErrorBox error={error} /></div>;
  if (!data) return <Loading />;
  return <>{children(data)}</>;
}

export function ErrorBox({ error }: Readonly<{ error: string }>) {
  return <div className="callout danger">{error}</div>;
}

export function Meter({ value, warn, label }: Readonly<{ value: number; warn?: boolean; label?: string }>) {
  const pct = Math.min(100, Math.max(0, Math.round(value * 100)));
  return (
    <div className={`meter ${warn ? "warn" : ""}`} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}
      aria-label={label ?? "Usage"} aria-valuetext={`${pct}%`}>
      <span style={{ width: `${Math.min(100, Math.max(1, value * 100))}%` }} />
    </div>
  );
}

/** Props that make a table row (or any element) operable from the keyboard: Tab reaches it,
 *  Enter or Space activates it, like a click. Spread onto the element next to its onClick. */
export function activatable(onActivate: () => void) {
  return {
    tabIndex: 0,
    onKeyDown: (e: KeyboardEvent<HTMLElement>) => {
      if (e.target !== e.currentTarget) return; // a button inside the row keeps its own keys
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onActivate(); }
    },
  };
}

export function Drawer({ onClose, title, sub, children }: Readonly<{ onClose: () => void; title: ReactNode; sub?: ReactNode; children: ReactNode }>) {
  const ref = useDialog<HTMLElement>(onClose);
  return (
    <>
      <div className="drawer-backdrop" onMouseDown={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined} ref={ref} tabIndex={-1}>
        <div className="drawer-head">
          <div style={{ flex: 1, minWidth: 0 }}><h2>{title}</h2>{sub && <div className="muted" style={{ marginTop: 4 }}>{sub}</div>}</div>
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

export function Modal({ title, onClose, children, footer }: Readonly<{ title: string; onClose: () => void; children: ReactNode; footer: ReactNode }>) {
  const ref = useDialog<HTMLDivElement>(onClose);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1}>
        <div className="card-head"><h2>{title}</h2></div>
        <div className="card-body">{children}</div>
        <div className="modal-foot">{footer}</div>
      </div>
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Dialog behaviour: focus moves in when it opens, Tab stays inside it, Escape closes it, and
 *  focus goes back to whatever opened it. */
function useDialog<T extends HTMLElement>(onClose: () => void) {
  const ref = useRef<T>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const items = () => (node ? Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)) : []);
    // Skip the close button when something more useful (a field) is available.
    (items().find((el) => !el.hasAttribute("aria-label")) ?? items()[0] ?? node)?.focus();
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") { close.current(); return; }
      if (e.key !== "Tab" || !node) return;
      const list = items();
      if (!list.length) { e.preventDefault(); return; }
      const first = list[0]!, last = list[list.length - 1]!;
      if (e.shiftKey && (document.activeElement === first || document.activeElement === node)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      else if (!node.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); opener?.focus?.(); };
  }, []);
  return ref;
}

export function Pager({ total, limit, offset, onChange }: Readonly<{ total: number; limit: number; offset: number; onChange: (o: number) => void }>) {
  if (total <= limit) return null;
  return (
    <div className="pager">
      <span>{offset + 1}–{Math.min(total, offset + limit)} of {total.toLocaleString()}</span>
      <button className="small" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Prev</button>
      <button className="small" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
    </div>
  );
}

export function Copy({ text }: Readonly<{ text: string }>) {
  return (
    <button className="small" onClick={() => navigator.clipboard?.writeText(text)} title="Copy to clipboard">Copy</button>
  );
}
