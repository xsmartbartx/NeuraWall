// Typed client for the NeuraWall REST API (/api/v1).

const TOKEN_KEY = "neurawall.token";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: session lasts for this tab only */
  }
  memoryToken = token;
}

let memoryToken: string | null = readToken();
let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (fn: () => void) => (onUnauthorized = fn);
export const hasToken = () => Boolean(memoryToken);

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (memoryToken) headers.set("Authorization", `Bearer ${memoryToken}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  const res = await fetch(`/api/v1${path}`, { ...init, headers, body });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/sso")) onUnauthorized();
    const detail = Array.isArray(data.details) && data.details.length
      ? `: ${data.details.map((d: { loc: string[]; msg: string }) => `${d.loc.join(".")} ${d.msg}`).join("; ")}`
      : "";
    throw new ApiError(res.status, data.error ?? "error", (data.message ?? res.statusText) + detail);
  }
  return data as T;
}

// ---------------------------------------------------------------- types

export type Action = "allow" | "alert" | "rate_limit" | "drop" | "quarantine";
export type Mode = "enforce" | "alert_only";
export type Severity = "low" | "medium" | "high" | "critical";

export interface Me {
  id: number; email: string; name: string; role: string;
  must_change_password: boolean; permissions: string[];
}

export interface RuleMatch {
  src_cidrs?: string[]; dst_cidrs?: string[]; dst_ports?: number[]; protocols?: string[];
  directions?: string[]; sni_suffixes?: string[]; dns_suffixes?: string[];
  http_path_prefixes?: string[]; ja3?: string[]; labels?: string[];
  min_label_confidence?: number; min_anomaly_score?: number | null;
}

export interface Rule {
  id: string; name: string; description: string; rationale: string; priority: number;
  action: Action; mode: Mode; match: RuleMatch; enabled: boolean; version: number;
  created_by: string; approved_by: string | null; created_at: number;
}

export interface Simulation {
  flows_evaluated: number; flows_matched: number; blast_radius: number; legitimate_matched: number;
  would_block: number; affected_sources: number; affected_destinations: number;
  sample_matches: string[]; exceeds_threshold: boolean; threshold: number;
}

export interface DraftRow {
  id: string; status: "pending" | "approved" | "rejected"; created_by: string; created_at: number;
  decided_by: string | null; decided_at: number | null; decision_note: string | null;
  rule_id: string | null; alert_id: number | null;
  draft: {
    draft_id: string; name: string; rationale: string; action: Action; mode: Mode; priority: number;
    match: RuleMatch; confidence: number; source: "llm" | "heuristic" | "operator";
    evidence_flow_ids: string[]; simulation: Simulation | null;
  };
}

export interface Alert {
  id: number; status: string; severity: Severity; title: string; summary: string;
  summary_source: string; labels: string[]; src_ip: string; dst_ip: string; node_id: string;
  flow_count: number; blocked_count: number; max_score: number; first_seen: number; last_seen: number;
  assignee: string | null; recommended_actions: string[];
  narrative: { title: string; narrative: string; timeline: string[]; source: string } | null;
  draft_id: string | null; tier3_pending: boolean;
}

export interface FlowSummary {
  flow_id: string; node_id: string; ts: number; src_ip: string; dst_ip: string; dst_port: number;
  protocol: string; bytes: number; action: Action; enforced: boolean; rule_id: string | null;
  anomaly_score: number | null; labels: string[]; host: string | null; alert_id: number | null;
}

export interface Attribution { feature: string; contribution: number; value?: string | number | null }

export interface FlowDetail extends FlowSummary {
  flow: Record<string, unknown> & { l7?: Record<string, Record<string, unknown> | null> | null };
  signals: {
    anomaly: { score: number; confidence: number; top_features: Attribution[]; model_version: string } | null;
    classifications: { label: string; confidence: number; detector: string; attributions: Attribution[] }[];
  };
  verdict: { action: Action; rule_id: string | null; enforced: boolean; reasons: string[] };
}

export interface Bundle {
  version: number; created_at: number; created_by: string; rule_count: number; status: string;
  rollout_percent: number; note: string; key_id: string;
}

export interface NodeRow {
  id: string; name: string; hostname: string; agent_version: string; backend: string;
  applied_version: number; up_to_date: boolean; enrolled_at: number; last_seen: number | null;
  status: "online" | "offline" | "revoked"; stats: Record<string, unknown>;
}

export interface AuditRow { seq: number; ts: number; actor: string; action: string; target: string; detail: Record<string, unknown>; hash: string }

export interface UserRow { id: number; email: string; name: string; role: string; active: boolean; must_change_password: boolean; created_at: number; last_login: number | null }

export interface Dashboard {
  window_hours: number; total_flows: number; enforced_blocks: number; by_action: Record<string, number>;
  labels: Record<string, number>; top_sources: { ip: string; count: number }[];
  timeline: { ts: number; allow: number; alert: number; blocked: number }[]; bucket_seconds: number;
  open_alerts: Record<string, number>; pending_drafts: number; nodes: { total: number; online: number };
  active_rules: number; bundle_version: number; advisor_mode: string; tier1_trained: boolean;
}

export interface SystemInfo {
  version: string; environment: string; hostname: string; uptime_seconds: number;
  advisor: { mode: string; provider: string; model: string | null; budget_remaining: number; last_error: string | null };
  signing_key_id: string; four_eyes: boolean; demo_mode: boolean; tier1_trained: boolean; database: string;
}

export interface HygieneFinding { rule_id: string; kind: string; detail: string; related_rule_id: string | null }
export interface Page<T> { total: number; items: T[] }
