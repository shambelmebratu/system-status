'use client';

import { FormEvent, useState } from 'react';
import { CodeBox, Empty, Field, Icon, Modal } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';
import { generatePassword } from '../lib/password';
import { ROLE_INFO, type Me, type Role } from '../lib/types';

const ROLES: Role[] = ['admin', 'operator', 'viewer'];

function RolePicker({ value, onChange, disabled }: { value: Role; onChange: (r: Role) => void; disabled?: boolean }) {
  return (
    <div className="method" role="radiogroup" aria-label="Role">
      {ROLES.map(r => (
        <button type="button" key={r} role="radio" aria-checked={value === r} disabled={disabled} className={value === r ? 'on' : ''} onClick={() => onChange(r)} style={disabled ? { opacity: 0.6, cursor: 'not-allowed' } : undefined}>
          <b>{ROLE_INFO[r].label}</b><span>{ROLE_INFO[r].blurb}</span>
        </button>))}
    </div>
  );
}

export function Users() {
  const { me, toast } = useApp();
  const list = usePoll(() => api<Me[]>('/users'), [], 20000);
  const [editing, setEditing] = useState<Me | 'new' | null>(null);
  const [created, setCreated] = useState<{ email: string; password: string } | null>(null);
  const users = list.value;
  const admins = users?.filter(u => u.role === 'admin' && u.active).length ?? 0;

  return (
    <>
      <div className="topbar"><div><h1>Users</h1><p className="muted sm">Who can sign in, and what each person is allowed to do.</p></div><span className="grow" />
        <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />Add user</button></div>
      <div className="grid g3" style={{ marginBottom: 16 }}>
        {ROLES.map(r => <div key={r} className="card"><div className="card-head" style={{ marginBottom: 6 }}><span className={`role-pill ${r}`}>{ROLE_INFO[r].label}</span><span className="grow" /><b>{users?.filter(u => u.role === r && u.active).length ?? '–'}</b></div><p className="muted sm">{ROLE_INFO[r].blurb}</p></div>)}
      </div>
      <div className="card">
        {list.error ? <div className="err">{list.error}</div> : !users ? <p className="muted">Loading…</p> : users.length === 0 ? <Empty title="No users" /> : (
          <table className="tbl"><thead><tr><th>User</th><th>Role</th><th>Status</th><th className="hide-sm">Last sign-in</th><th /></tr></thead><tbody>
            {users.map(u => (
              <tr key={u.id} style={u.active ? undefined : { opacity: 0.55 }}>
                <td><div className="name">{u.name || u.email.split('@')[0]}{u.id === me.id && <> <span className="tag">you</span></>}<small>{u.email}</small></div></td>
                <td><span className={`role-pill ${u.role}`}>{ROLE_INFO[u.role].label}</span></td>
                <td className="sm">{!u.active ? <span className="bad">Disabled</span> : u.must_change_password ? <span className="warn">Must set password</span> : <span className="good">Active</span>}</td>
                <td className="hide-sm sm muted">{u.last_login_at ? timeAgo(u.last_login_at) : 'never'}</td>
                <td style={{ textAlign: 'right' }}><button className="btn sm" onClick={() => setEditing(u)}>Edit</button></td>
              </tr>))}
          </tbody></table>
        )}
        {users && admins === 1 && <p className="muted sm" style={{ marginTop: 12 }}>Only one active admin exists. Add a second one so you can never be locked out.</p>}
      </div>
      {editing && <UserForm existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={(credentials) => { setEditing(null); if (credentials) setCreated(credentials); void list.reload(); }} />}
      {created && (
        <Modal title="User created" onClose={() => setCreated(null)}>
          <p className="muted">Send these sign-in details to the new user through a private channel. The temporary password is shown <b>only now</b>; they will be asked to choose their own at first sign-in.</p>
          <CodeBox value={`Email: ${created.email}\nTemporary password: ${created.password}`} />
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}><button className="btn primary" onClick={() => { setCreated(null); toast('Remember to share the temporary password'); }}>Done</button></div>
        </Modal>)}
    </>
  );
}

function UserForm({ existing, onClose, onSaved }: { existing?: Me; onClose: () => void; onSaved: (credentials?: { email: string; password: string }) => void }) {
  const { me, toast } = useApp();
  const isSelf = existing?.id === me.id;
  const [email, setEmail] = useState(existing?.email ?? '');
  const [name, setName] = useState(existing?.name ?? '');
  const [role, setRole] = useState<Role>(existing?.role ?? 'viewer');
  const [active, setActive] = useState(existing?.active ?? true);
  const [password, setPassword] = useState(() => (existing ? '' : generatePassword()));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(''); setBusy(true);
    try {
      if (existing) {
        await put(`/users/${existing.id}`, { name, ...(isSelf ? {} : { role, active }), ...(password ? { password } : {}) });
        toast(password ? `Saved. Share the new temporary password with ${existing.email}.` : 'User updated');
        onSaved(password ? { email: existing.email, password } : undefined);
      } else { await post('/users', { email, name, role, password }); onSaved({ email, password }); }
    } catch (caught) { setError((caught as Error).message); } finally { setBusy(false); }
  }
  async function remove() {
    if (!existing || !window.confirm(`Delete ${existing.email}? They are signed out immediately and this cannot be undone.`)) return;
    try { await del(`/users/${existing.id}`); toast('User deleted'); onSaved(); } catch (caught) { setError((caught as Error).message); }
  }

  return (
    <Modal title={existing ? `Edit ${existing.email}` : 'Add a user'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="form-grid">
          <Field label="Email"><input type="email" value={email} onChange={e => setEmail(e.target.value)} required disabled={!!existing} autoFocus={!existing} /></Field>
          <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder="Full name" maxLength={100} autoFocus={!!existing} /></Field>
        </div>
        <div className="field">Role{isSelf && <small>You cannot change your own role. Ask another admin.</small>}<RolePicker value={role} onChange={setRole} disabled={isSelf} /></div>
        {existing && !isSelf && <label className="check"><input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)} />Account enabled <span className="muted">(disabled users are signed out and cannot sign in)</span></label>}
        <Field label={existing ? 'Reset password (optional)' : 'Temporary password'} hint={existing ? 'Leave empty to keep the current password. A reset signs the user out and they must choose a new password.' : 'They must replace it at first sign-in. At least 12 characters.'}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input style={{ flex: 1, fontFamily: 'var(--mono)' }} value={password} onChange={e => setPassword(e.target.value)} minLength={password ? 12 : undefined} required={!existing} autoComplete="off" />
            <button type="button" className="btn" onClick={() => setPassword(generatePassword())}>Generate</button>
          </div>
        </Field>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'space-between' }}>
          {existing && !isSelf ? <button type="button" className="btn danger" onClick={remove}>Delete user</button> : <span />}
          <span style={{ display: 'flex', gap: 10 }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : existing ? 'Save changes' : 'Create user'}</button></span>
        </div>
      </form>
    </Modal>
  );
}
