import { useState, type FormEvent } from "react";
import { Logo } from "../components/Layout";
import { api } from "../lib/api";
import { useAuth } from "../lib/hooks";

export function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
      await api("/auth/password", { method: "POST", json: { current_password: current, new_password: next } });
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
