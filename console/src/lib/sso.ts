// "Sign in with NEXORA": the browser is sent to the account app, which returns it here
// with a short-lived Clerk token in the URL *fragment* (never sent to a server or logged).
// A random `state` we generated before leaving is echoed back; a token we did not ask
// for (login CSRF) is rejected.

const STATE_KEY = "neurawall.sso.state";

export interface SsoConfig {
  enabled: boolean;
  login_url: string | null;
  jit: boolean;
  local_login: "enabled" | "admin_only";
  demo: boolean;
}

function randomState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function startSso(loginUrl: string): void {
  const state = randomState();
  try {
    sessionStorage.setItem(STATE_KEY, state);
  } catch {
    throw new Error("Single sign-on needs browser session storage");
  }
  const url = new URL(loginUrl);
  url.searchParams.set("state", state);
  window.location.assign(url.toString());
}

/**
 * Reads and removes a returned token from the URL fragment. The fragment is cleared
 * immediately, whatever the outcome, so the token never stays in the address bar or
 * browser history. Returns the token only if `state` matches the one we stored.
 */
export function consumeSsoFragment(): string | null {
  const hash = window.location.hash;
  if (!hash.startsWith("#sso_token=")) return null;
  window.history.replaceState(null, "", window.location.pathname + window.location.search);

  const params = new URLSearchParams(hash.slice(1));
  const token = params.get("sso_token");
  const state = params.get("state");
  let expected: string | null = null;
  try {
    expected = sessionStorage.getItem(STATE_KEY);
    sessionStorage.removeItem(STATE_KEY);
  } catch {
    /* storage unavailable: cannot verify state, so refuse */
  }
  if (!token || !state || !expected || state !== expected) return null;
  return token;
}
