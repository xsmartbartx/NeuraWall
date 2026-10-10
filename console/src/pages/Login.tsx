import { useEffect, useState, type FormEvent } from "react";
import { Logo } from "../components/Layout";
import { api, setToken } from "../lib/api";
import { useAuth } from "../lib/hooks";
import { consumeSsoFragment, startSso, type SsoConfig } from "../lib/sso";

export function Login() {
  const { login, loginWithSso, loginDemo } = useAuth();
  const [sso, setSso] = useState<SsoConfig | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // Returning from the account app with a token in the fragment: finish the sign-in.
    const token = consumeSsoFragment();
    if (token) {
      setBusy(true);
      loginWithSso(token)
        .catch(() => setError("Single sign-on was not accepted for this account. Use your password instead."))
        .finally(() => setBusy(false));
    }
    api<SsoConfig>("/auth/sso/config").then(setSso).catch(() => setSso(null));
  }, [loginWithSso]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try { await login(email, password); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <div className="brand"><Logo size={32} /><div>NeuraWall<small>Operator console</small></div></div>
        <label className="field">Email
          <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        </label>
        <label className="field">Password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <div className="error-text" role="alert">{error}</div>}
        <button className="primary" disabled={busy} type="submit" style={{ justifyContent: "center" }}>
          {busy ? <span className="spinner" /> : "Sign in"}
        </button>
        {sso?.enabled && sso.login_url && (
          <button type="button" className="ghost" disabled={busy} style={{ justifyContent: "center" }}
            onClick={() => { try { startSso(sso.login_url!); } catch (err) { setError((err as Error).message); } }}>
            Sign in with NEXORA
          </button>
        )}
        {sso?.demo && (
          <button type="button" disabled={busy} style={{ justifyContent: "center" }}
            onClick={async () => { setBusy(true); setError(null); try { await loginDemo(); } catch (err) { setError((err as Error).message); } finally { setBusy(false); } }}>
            Try the demo
          </button>
        )}
        {sso?.demo && <p className="muted" style={{ margin: 0, fontSize: 12 }}>The demo is read-only and shows synthetic traffic. Nothing you do here touches a real network.</p>}
        {sso?.enabled && sso.local_login === "admin_only" && (
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            Team members sign in with NEXORA. Password sign-in is kept for administrators.
          </p>
        )}
        <p className="faint" style={{ margin: 0, fontSize: 12 }}>
          First login? The bootstrap admin password is in <code>initial-admin-password.txt</code> in the server's data directory.
        </p>
      </form>
    </div>
  );
}

export function ForcePasswordChange() {
  const { me, refresh, logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (next !== confirm) { setError("New passwords do not match"); return; }
    try {
      const res = await api<{ access_token: string }>("/auth/password", { method: "POST", json: { current_password: current, new_password: next } });
      setToken(res.access_token); // all earlier sessions were revoked
      await refresh();
    } catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <div className="brand"><Logo size={32} /><div>Set a new password<small>{me?.email}</small></div></div>
        <p className="muted" style={{ margin: 0 }}>Your password was set by an administrator. Choose your own to continue: at least 12 characters mixing three of lower, upper, digits and symbols.</p>
        <label className="field">Current password<input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required /></label>
        <label className="field">New password<input type="password" autoComplete="new-password" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} required /></label>
        <label className="field">Confirm new password<input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required /></label>
        {error && <div className="error-text" role="alert">{error}</div>}
        <div className="row"><button className="primary" type="submit">Update password</button><button type="button" className="ghost" onClick={logout}>Sign out</button></div>
      </form>
    </div>
  );
}
