'use client';

import { FormEvent, useEffect, useState } from 'react';
import { CodeBox, Field } from '../components/ui';
import { post } from '../lib/api';
import { useApp } from '../lib/app';

export function Settings({ email }: { email: string }) {
  const { toast, data } = useApp();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [error, setError] = useState('');
  const [origin, setOrigin] = useState('');
  useEffect(() => setOrigin(window.location.origin), []);

  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    try { await post('/auth/password', { current_password: current, new_password: next }); setCurrent(''); setNext(''); toast('Password changed. Other sessions were signed out.'); }
    catch (caught) { setError((caught as Error).message); }
  }

  return (
    <>
      <div className="topbar"><h1>Settings</h1></div>
      <div className="grid g2">
        <section className="card"><div className="card-head"><h2>Account</h2></div>
          <p className="muted" style={{ marginBottom: 14 }}>Signed in as <b style={{ color: 'var(--ink)' }}>{email}</b></p>
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <Field label="Current password"><input type="password" value={current} onChange={e => setCurrent(e.target.value)} autoComplete="current-password" required /></Field>
            <Field label="New password" hint="At least 12 characters."><input type="password" value={next} onChange={e => setNext(e.target.value)} minLength={12} autoComplete="new-password" required /></Field>
            {error && <div className="err" role="alert">{error}</div>}
            <button className="btn primary" style={{ alignSelf: 'flex-start' }}>Change password</button>
          </form>
        </section>
        <section className="card"><div className="card-head"><h2>Public status page</h2></div>
          <p className="muted" style={{ marginBottom: 12 }}>Share uptime with customers. Enable “Show on the public status page” on any service.</p>
          <CodeBox value={`${origin}/status`} />
          <p className="sm muted" style={{ marginTop: 14 }}>{data?.services.filter(s => s.public).length ?? 0} of {data?.services.length ?? 0} services are public.</p>
        </section>
      </div>
    </>
  );
}
