'use client';

import { FormEvent, useState } from 'react';
import { post } from '../lib/api';

export function Login({ company, onSignedIn }: { company: string; onSignedIn: () => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    try { await post('/auth/login', { email, password }); setPassword(''); onSignedIn(); }
    catch (caught) { setError((caught as Error).message); }
    finally { setBusy(false); }
  }

  return (
    <main className="login">
      <section className="login-art">
        <div className="brand"><span className="logo">★</span>{company}</div>
        <div>
          <h1>Know before <em>they know.</em></h1>
          <p>Uptime, host metrics, incidents and alerts for every server and service, in one place.</p>
        </div>
        <small className="muted">Install an agent on any server in one command.</small>
      </section>
      <form className="login-form" onSubmit={submit}>
        <div><h2>Welcome back</h2><p className="muted">Sign in to the control plane.</p></div>
        <label className="field">Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} autoComplete="username" required autoFocus /></label>
        <label className="field">Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        {error && <div className="err" role="alert">{error}</div>}
        <button className="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <a className="sm muted" href="/status">View public status page →</a>
      </form>
    </main>
  );
}
