import { Fragment, useState } from "react";
import { Badge, Card, Copy, ErrorBox, Loading, Modal, PageHead } from "../components/ui";
import { api, type UserRow } from "../lib/api";
import { ago } from "../lib/format";
import { useAction, useApi, useAuth } from "../lib/hooks";

const ROLES: [string, string][] = [
  ["viewer", "Read-only access to dashboards, alerts, flows and rules."],
  ["analyst", "Viewer + triage alerts and use the AI advisor."],
  ["operator", "Analyst + author rule drafts and manage the fleet."],
  ["approver", "Analyst + approve/reject drafts, change rules, read audit."],
  ["admin", "Everything, including user management."],
];

export function Users() {
  const { me } = useAuth();
  const { run, busy } = useAction();
  const { data, error, reload } = useApi<UserRow[]>("/users");
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ email: "", name: "", role: "analyst", password: "" });
  const [temp, setTemp] = useState<{ email: string; password: string } | null>(null);

  const patch = async (u: UserRow, body: Partial<UserRow>) => {
    if (await run(() => api(`/users/${u.id}`, { method: "PATCH", json: body }), "User updated")) reload();
  };

  return (
    <>
      <PageHead title="Users" desc="Role-based access. Approving rule changes is a separate permission from authoring them." actions={<button className="primary" onClick={() => setCreating(true)}>Add user</button>} />
      <Card pad={false}>
        {error ? <div className="card-body"><ErrorBox error={error} /></div> : !data ? <Loading /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
            <tbody>
              {data.map((u) => (
                <tr key={u.id}>
                  <td><div>{u.name || u.email} {u.auth_provider === "nexora" && <Badge kind="info">NEXORA</Badge>}</div><div className="faint">{u.email}</div></td>
                  <td>
                    <select value={u.role} disabled={busy || u.id === me?.id} onChange={(e) => patch(u, { role: e.target.value })} aria-label={`Role for ${u.email}`}>
                      {ROLES.map(([r]) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td>{u.active ? <Badge kind="active" dot /> : <Badge kind="revoked">disabled</Badge>} {u.must_change_password && <Badge kind="pending">password reset pending</Badge>}</td>
                  <td className="muted">{ago(u.last_login)}</td>
                  <td className="row" style={{ flexWrap: "nowrap" }}>
                    {u.id !== me?.id && <button className="small" disabled={busy} onClick={() => patch(u, { active: !u.active })}>{u.active ? "Disable" : "Enable"}</button>}
                    {u.auth_provider === "local" && <button className="small" disabled={busy} onClick={async () => {
                      const r = await run(() => api<{ temporary_password: string }>(`/users/${u.id}/reset-password`, { method: "POST" }));
                      if (r) { setTemp({ email: u.email, password: r.temporary_password }); reload(); }
                    }}>Reset password</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      <Card title="Roles">
        <dl className="kv">{ROLES.map(([r, d]) => <Fragment key={r}><dt className="mono">{r}</dt><dd>{d}</dd></Fragment>)}</dl>
      </Card>
      {creating && (
        <Modal title="Add user" onClose={() => setCreating(false)} footer={<>
          <button onClick={() => setCreating(false)}>Cancel</button>
          <button className="primary" disabled={busy} onClick={async () => {
            if (await run(() => api("/users", { method: "POST", json: form }), "User created")) {
              setCreating(false); setForm({ email: "", name: "", role: "analyst", password: "" }); reload();
            }
          }}>Create</button></>}>
          <label className="field">Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
          <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
          <label className="field">Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map(([r]) => <option key={r}>{r}</option>)}</select></label>
          <label className="field">Temporary password (min 12 chars; user must change it)<input type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        </Modal>
      )}
      {temp && (
        <Modal title="Temporary password" onClose={() => setTemp(null)} footer={<button className="primary" onClick={() => setTemp(null)}>Done</button>}>
          <p style={{ margin: 0 }}>Share this with <b>{temp.email}</b> over a secure channel. It is shown once and must be changed at next sign-in.</p>
          <div className="row"><code style={{ fontSize: 15 }}>{temp.password}</code><Copy text={temp.password} /></div>
        </Modal>
      )}
    </>
  );
}
