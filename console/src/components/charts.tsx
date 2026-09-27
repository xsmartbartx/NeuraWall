import { useState } from "react";
import { num } from "../lib/format";

type Point = { ts: number; allow: number; alert: number; blocked: number };

const SERIES = [
  { key: "allow", label: "Allowed", color: "var(--allow)", opacity: 0.35 },
  { key: "alert", label: "Alerted", color: "var(--alert)", opacity: 0.9 },
  { key: "blocked", label: "Blocked", color: "var(--block)", opacity: 1 },
] as const;

/** Stacked bar timeline of verdicts per bucket. */
export function VerdictTimeline({ points, bucket }: { points: Point[]; bucket: number }) {
  const [tip, setTip] = useState<{ x: number; y: number; p: Point } | null>(null);
  const W = 900, H = 220, L = 44, B = 22, T = 8;
  const max = Math.max(1, ...points.map((p) => p.allow + p.alert + p.blocked));
  const niceMax = niceCeil(max);
  const bw = (W - L) / Math.max(1, points.length);
  const y = (v: number) => T + (H - T - B) * (1 - v / niceMax);
  const ticks = [0, niceMax / 2, niceMax];
  const labelEvery = Math.ceil(points.length / 8);
  const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString(undefined, bucket >= 3600
    ? { hour: "2-digit" } : { hour: "2-digit", minute: "2-digit" });

  return (
    <div className="chart" onMouseLeave={() => setTip(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Verdicts over time">
        {ticks.map((t) => (
          <g key={t}>
            <line className="grid-line" x1={L} x2={W} y1={y(t)} y2={y(t)} />
            <text className="tick" x={L - 6} y={y(t) + 3} textAnchor="end">{num(t)}</text>
          </g>
        ))}
        {points.map((p, i) => {
          let acc = 0;
          const x = L + i * bw;
          return (
            <g key={p.ts} onMouseMove={(e) => setTip({ x: e.clientX, y: e.clientY, p })}>
              <rect x={x} y={T} width={bw} height={H - T - B} fill="transparent" />
              {SERIES.map((s) => {
                const v = p[s.key];
                if (!v) return null;
                const y1 = y(acc + v), h = y(acc) - y1;
                acc += v;
                return <rect key={s.key} x={x + 1} y={y1} width={Math.max(1, bw - 2)} height={Math.max(1, h)}
                  fill={s.color} opacity={s.opacity} rx={1} />;
              })}
              {i % labelEvery === 0 && <text className="tick" x={x + bw / 2} y={H - 6} textAnchor="middle">{fmt(p.ts)}</text>}
            </g>
          );
        })}
      </svg>
      <div className="legend" style={{ marginTop: 8 }}>
        {SERIES.map((s) => <span key={s.key}><i style={{ background: s.color, opacity: s.opacity }} />{s.label}</span>)}
      </div>
      {tip && (
        <div className="chart-tip" style={{ left: tip.x + 12, top: tip.y + 12 }}>
          <div className="mono faint">{new Date(tip.p.ts * 1000).toLocaleString()}</div>
          {SERIES.map((s) => <div key={s.key}>{s.label}: <b className="mono">{num(tip.p[s.key])}</b></div>)}
        </div>
      )}
    </div>
  );
}

export function BarList({ items, color = "var(--alert)", onClick }: {
  items: { label: string; value: number }[]; color?: string; onClick?: (label: string) => void;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <div className="muted">No data in this window.</div>;
  return (
    <div className="bar-list">
      {items.map((i) => (
        <div key={i.label} className="item" style={{ cursor: onClick ? "pointer" : undefined }} onClick={() => onClick?.(i.label)}>
          <span className="mono truncate">{i.label}</span>
          <span className="mono muted">{num(i.value)}</span>
          <div className="track"><div className="fill" style={{ width: `${(i.value / max) * 100}%`, background: color }} /></div>
        </div>
      ))}
    </div>
  );
}

function niceCeil(v: number): number {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
