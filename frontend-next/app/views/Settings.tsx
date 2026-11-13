'use client';

import { FormEvent, Fragment, useEffect, useState } from 'react';
import { JoinCommands, expiryText, useActiveEnrollment, useControlPlaneUrl } from '../components/join';
import { RetentionCard } from '../components/retention';
import { CodeBox, Field } from '../components/ui';
import { post, put } from '../lib/api';
import { ROLE_INFO } from '../lib/types';
import { timeAgo } from '../lib/format';
import { useApp, useLimits } from '../lib/app';

export function Settings() {
  const { toast, data, me, canOperate, isAdmin, reloadMe } = useApp();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [error, setError] = useState('');
  const [origin, setOrigin] = useState('');
  const [name, setName] = useState(me.name);
  const [email, setEmail] = useState(me.email);
  const [emailPassword, setEmailPassword] = useState('');
  const [profileError, setProfileError] = useState('');
  useEffect(() => setOrigin(window.location.origin), []);

  async function saveProfile(event: FormEvent) {
    event.preventDefault(); setProfileError('');
    try { await put('/auth/profile', { name, email: email !== me.email ? email : null, current_password: emailPassword }); setEmailPassword(''); toast('Profile saved'); await reloadMe(); }
    catch (caught) { setProfileError((caught as Error).message); }
  }
  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    try { await post('/auth/password', { current_password: current, new_password: next }); setCurrent(''); setNext(''); toast('Password changed. Other sessions were signed out.'); }
    catch (caught) { setError((caught as Error).message); }
  }

  return (
    <>
      <div className="topbar"><h1>Settings</h1></div>
      <div className="grid g2">
        <section className="card"><div className="card-head"><h2>Profile</h2><span className="grow" /><span className={`role-pill ${me.role}`}>{ROLE_INFO[me.role].label}</span></div>
          <form onSubmit={saveProfile} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} maxLength={100} placeholder="Your name" /></Field>
            <Field label="Email" hint="This is what you sign in with."><input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></Field>
            {email !== me.email && <Field label="Current password" hint="Needed to change your email."><input type="password" value={emailPassword} onChange={e => setEmailPassword(e.target.value)} autoComplete="current-password" required /></Field>}
            {profileError && <div className="err" role="alert">{profileError}</div>}
            <button className="btn primary" style={{ alignSelf: 'flex-start' }}>Save profile</button>
          </form>
          <p className="muted sm" style={{ marginTop: 14 }}>{ROLE_INFO[me.role].blurb}</p>
        </section>
        <section className="card"><div className="card-head"><h2>Password</h2></div>
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <Field label="Current password"><input type="password" value={current} onChange={e => setCurrent(e.target.value)} autoComplete="current-password" required /></Field>
            <Field label="New password" hint="At least 12 characters. Signs out your other sessions."><input type="password" value={next} onChange={e => setNext(e.target.value)} minLength={12} autoComplete="new-password" required /></Field>
            {error && <div className="err" role="alert">{error}</div>}
            <button className="btn primary" style={{ alignSelf: 'flex-start' }}>Change password</button>
          </form>
        </section>
        <section className="card"><div className="card-head"><h2>Public status page</h2></div>
          <p className="muted" style={{ marginBottom: 12 }}>The only page that can be opened without signing in. It shows just the servers and services you tick “Show on the public status page” for (name, status and uptime). Turn it off completely with <code>PUBLIC_STATUS_ENABLED=false</code>.</p>
          <CodeBox value={`${origin}/status`} />
          <p className="sm muted" style={{ marginTop: 14 }}>{(data?.services.filter(s => s.public).length ?? 0) + (data?.servers.filter(s => s.public).length ?? 0)} item(s) are public.</p>
        </section>
      </div>
      {canOperate && <JoinTokens />}
      {isAdmin && <RetentionCard />}
    </>
  );
}

function JoinTokens() {
  const { toast } = useApp();
  const [base] = useControlPlaneUrl();
  const enrollment = useActiveEnrollment();
  const [label, setLabel] = useState('');
  const lim = useLimits();
  const [minutes, setMinutes] = useState('');
  const choices = [...new Set([10, lim.enrollDefault, 60, lim.enrollMax])].filter(m => m <= lim.enrollMax).sort((a, b) => a - b);
  const label_ = (m: number) => (m < 60 ? `in ${m} minutes` : m % 60 === 0 && m < 1440 ? `in ${m / 60} hour${m === 60 ? '' : 's'}` : m === 1440 ? 'in 24 hours' : `in ${m} minutes`) + (m === lim.enrollMax ? ' (maximum)' : '');
  const [maxUses, setMaxUses] = useState('');
  const [openId, setOpenId] = useState<number | null>(null);

  async function create(event: FormEvent) {
    event.preventDefault();
    try {
      await post('/enrollments', { label, expires_minutes: Number(minutes || lim.enrollDefault), max_uses: maxUses ? Number(maxUses) : null });
      setLabel(''); setMaxUses(''); toast('Join token created'); await enrollment.reload();
    } catch (caught) { toast((caught as Error).message, true); }
  }

  return (
    <section className="card" style={{ marginTop: 16 }}>
      <div className="card-head"><h2>Agent join tokens</h2></div>
      <p className="muted sm" style={{ marginBottom: 14 }}>A join token lets a server register itself as a new monitor with a single command. Anyone holding an active token can add servers to this dashboard, so links are short-lived ({lim.enrollDefault} minutes by default, {Math.round(lim.enrollMax / 60)} hours at most). Add a server limit for extra safety and revoke links you no longer need. Revoking never disconnects servers that already joined.</p>
      <form onSubmit={create} className="form-grid" style={{ marginBottom: 16, alignItems: 'end' }}>
        <Field label="Label"><input value={label} onChange={e => setLabel(e.target.value)} placeholder="e.g. new web servers" /></Field>
        <Field label="Expires"><select value={minutes || String(lim.enrollDefault)} onChange={e => setMinutes(e.target.value)}>{choices.map(m => <option key={m} value={m}>{label_(m)}</option>)}</select></Field>
        <Field label="Max servers (optional)"><input type="number" min={1} value={maxUses} onChange={e => setMaxUses(e.target.value)} placeholder="unlimited" /></Field>
        <button className="btn primary">Create token</button>
      </form>
      {!enrollment.items?.length ? <p className="muted sm">No tokens yet.</p> : (
        <table className="tbl rowstack"><thead><tr><th>Token</th><th>Status</th><th>Used</th><th className="hide-sm">Last used</th><th /></tr></thead><tbody>
          {enrollment.items.map(t => (
            <Fragment key={t.id}>
              <tr>
                <td><div className="name">{t.label || 'Untitled'}<small>{t.created_by ? `by ${t.created_by} · ` : ''}<span className="mono">{t.token.slice(0, 8)}…</span></small></div></td>
                <td><span className={`pill ${t.active ? 'up' : 'unknown'}`}><i />{expiryText(t)}</span></td>
                <td>{t.uses}{t.max_uses ? ` / ${t.max_uses}` : ''}</td><td className="hide-sm muted">{t.last_used_at ? timeAgo(t.last_used_at) : 'never'}</td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>{t.active && <><button className="btn sm" onClick={() => setOpenId(openId === t.id ? null : t.id)}>{openId === t.id ? 'Hide command' : 'Show command'}</button> <button className="btn sm danger" onClick={() => enrollment.revoke(t.id)}>Revoke</button></>}</td>
              </tr>
              {openId === t.id && <tr><td colSpan={5}><JoinCommands token={t.token} base={base} /></td></tr>}
            </Fragment>
          ))}
        </tbody></table>
      )}
    </section>
  );
}
