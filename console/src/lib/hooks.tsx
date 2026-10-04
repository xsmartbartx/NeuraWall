import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, ApiError, hasToken, setToken, setUnauthorizedHandler, type Me } from "./api";

// ---------------------------------------------------------------- data fetching

export function useApi<T>(path: string | null, opts: { poll?: number } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);

  const load = useCallback(async () => {
    if (!path) return;
    const mine = ++seq.current;
    try {
      const d = await api<T>(path);
      if (mine === seq.current) { setData(d); setError(null); }
    } catch (e) {
      if (mine === seq.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (mine === seq.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    setLoading(true);
    load();
    if (!opts.poll) return;
    const id = window.setInterval(() => { if (!document.hidden) load(); }, opts.poll);
    return () => window.clearInterval(id);
  }, [load, opts.poll]);

  return { data, error, loading, reload: load, setData };
}

// ---------------------------------------------------------------- auth

interface AuthCtx {
  me: Me | null;
  ready: boolean;
  can: (perm: string) => boolean;
  login: (email: string, password: string) => Promise<Me>;
  /** Exchange a Clerk token (from the "Sign in with NEXORA" handoff) for a console session. */
  loginWithSso: (token: string) => Promise<Me>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const Auth = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);

  const logout = useCallback(() => { setToken(null); setMe(null); }, []);

  const refresh = useCallback(async () => {
    if (!hasToken()) { setReady(true); return; }
    try { setMe(await api<Me>("/auth/me")); } catch { logout(); } finally { setReady(true); }
  }, [logout]);

  useEffect(() => { setUnauthorizedHandler(logout); refresh(); }, [logout, refresh]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await api<{ access_token: string }>("/auth/login", { method: "POST", json: { email, password } });
    setToken(res.access_token);
    const m = await api<Me>("/auth/me");
    setMe(m);
    return m;
  }, []);

  const loginWithSso = useCallback(async (token: string) => {
    const res = await api<{ access_token: string }>("/auth/sso", { method: "POST", json: { token } });
    setToken(res.access_token);
    const m = await api<Me>("/auth/me");
    setMe(m);
    return m;
  }, []);

  const can = useCallback((perm: string) => Boolean(me?.permissions.includes(perm)), [me]);

  return <Auth.Provider value={{ me, ready, can, login, loginWithSso, logout, refresh }}>{children}</Auth.Provider>;
}

export function useAuth(): AuthCtx {
  const ctx = useContext(Auth);
  if (!ctx) throw new Error("useAuth outside provider");
  return ctx;
}

// ---------------------------------------------------------------- toasts

interface Toast { id: number; text: string; kind: "ok" | "error" }
const ToastCtx = createContext<(text: string, kind?: "ok" | "error") => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: "ok" | "error" = "ok") => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs, { id, text, kind }]);
    window.setTimeout(() => setItems((xs) => xs.filter((t) => t.id !== id)), kind === "error" ? 7000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => <div key={t.id} className={`toast ${t.kind === "error" ? "error" : ""}`}>{t.text}</div>)}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

/** Run a mutation with toast feedback; returns the result or undefined on error. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(async <T,>(fn: () => Promise<T>, success?: string): Promise<T | undefined> => {
    setBusy(true);
    try {
      const r = await fn();
      if (success) toast(success);
      return r;
    } catch (e) {
      toast(e instanceof ApiError || e instanceof Error ? e.message : String(e), "error");
      return undefined;
    } finally {
      setBusy(false);
    }
  }, [toast]);
  return { run, busy };
}

// ---------------------------------------------------------------- theme

export function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("neurawall.theme") ?? "dark"; } catch { return "dark"; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("neurawall.theme", theme); } catch { /* ignore */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}
