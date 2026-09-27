export function ago(ts: number | null | undefined): string {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function dateTime(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function num(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (Math.abs(n) >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (Math.abs(n) >= 1e4) return `${(n / 1e3).toFixed(1)}k`;
  return n.toLocaleString();
}

export function bytes(n: number): string {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export const pct = (x: number, digits = 1) => `${(x * 100).toFixed(digits)}%`;
export const human = (s: string) => s.replace(/_/g, " ");

export function matchSummary(m: Record<string, unknown>): string[] {
  const out: string[] = [];
  const list = (k: string, label: string) => {
    const v = m[k] as unknown[] | undefined;
    if (v && v.length) out.push(`${label} ${v.join(", ")}`);
  };
  list("src_cidrs", "src");
  list("dst_cidrs", "dst");
  list("dst_ports", "port");
  list("protocols", "proto");
  list("directions", "dir");
  list("sni_suffixes", "sni");
  list("dns_suffixes", "dns");
  list("http_path_prefixes", "path");
  list("ja3", "ja3");
  if ((m.labels as string[] | undefined)?.length) {
    const conf = m.min_label_confidence as number | undefined;
    out.push(`label ${(m.labels as string[]).join(" | ")}${conf ? ` ≥ ${conf}` : ""}`);
  }
  if (m.min_anomaly_score !== null && m.min_anomaly_score !== undefined) out.push(`anomaly ≥ ${m.min_anomaly_score}`);
  return out;
}
