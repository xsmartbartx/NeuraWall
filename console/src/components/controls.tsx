import { useId, useState, type ReactNode } from "react";
import { downloadCsv } from "../lib/api";
import { useToast } from "../lib/hooks";

/** An on/off switch. The state is announced (role=switch) and shown by position, not colour alone. */
export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; disabled?: boolean }) {
  const id = useId();
  return (
    <span className="toggle-row">
      <button id={id} type="button" role="switch" aria-checked={checked} className={`toggle ${checked ? "on" : ""}`}
        disabled={disabled} onClick={() => onChange(!checked)}><span className="knob" /></button>
      <label htmlFor={id}>{label}</label>
    </span>
  );
}

/** Shows a secret exactly once. It lives only in this component's state: not in the URL,
 *  not in storage, and gone when the dialog closes. */
export function SecretReveal({ label, secret, onDone }: { label: string; secret: string; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="stack">
      <div className="callout warn" role="status">Copy this {label} now. It is shown only once; if you lose it, rotate it.</div>
      <pre className="code" tabIndex={0} aria-label={label}>{secret}</pre>
      <div className="row">
        <button onClick={async () => { try { await navigator.clipboard.writeText(secret); setCopied(true); } catch { setCopied(false); } }}>Copy</button>
        <span className="faint" role="status">{copied ? "Copied" : ""}</span>
        <span className="right" />
        <button className="primary" onClick={onDone}>I have stored it</button>
      </div>
    </div>
  );
}

export function ExportButton({ path, filename }: { path: string; filename: string }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  return (
    <button disabled={busy} aria-busy={busy} onClick={async () => {
      setBusy(true);
      try {
        const cut = await downloadCsv(path, filename);
        toast(cut ? "Exported the first 50,000 rows. Narrow the filters for the rest." : "Export downloaded");
      } catch (e) {
        toast((e as Error).message, "error");
      } finally { setBusy(false); }
    }}>{busy ? "Preparing…" : "Export CSV"}</button>
  );
}
