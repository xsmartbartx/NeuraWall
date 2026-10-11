// Lookup tables for badge kinds and labels, kept out of JSX so the pages stay flat.

const lookup = (table: Record<string, string>, key: string, fallback: string): string => table[key] ?? fallback;

export const advisorBadge = (mode: string) =>
  lookup({ online: "llm", degraded: "alert", budget_reached: "alert" }, mode, "info");
export const advisorLabel = (mode: string) => lookup({ online: "Online", degraded: "Degraded" }, mode, "Offline");

export const deliveryBadge = (status: string) => lookup({ sent: "active", dead: "revoked" }, status, "pending");
export const deliveryLabel = (status: string, dead: string) => lookup({ sent: "delivered", dead }, status, "retrying");

export const linkBadge = (state: string) => lookup({ linked: "active", grace: "alert" }, state, "revoked");
export const linkLabel = (state: string) =>
  lookup({ linked: "linked", grace: "using last known plan" }, state, "not synced");

export const billingSource = (source: string) => lookup({ stripe: "via Stripe", nexora: "via NEXORA" }, source, "licence");
export const llmAccess = (access: string) =>
  lookup({ included: "Claude AI included, monthly budget", own_key: "Claude AI with your own key" }, access, "Offline AI advisor");

export function scoreBand<T>(score: number, good: T, ok: T, bad: T): T {
  if (score >= 90) return good;
  return score >= 70 ? ok : bad;
}
