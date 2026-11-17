'use client';

import { Logo } from '../components/logo';
import { FormEvent, useState } from 'react';
import { post } from '../lib/api';

export function Login({ company, onSignedIn }: { company: string; onSignedIn: () => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [ticket, setTicket] = useState<string | null>(null);   // the password step passed: ask for the authenticator code
  const [code, setCode] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    try {
      if (ticket) { await post('/auth/mfa', { mfa_token: ticket, code }); onSignedIn(); return; }
      const r = await post<{ mfa_required?: boolean; mfa_token?: string }>('/auth/login', { email, password });
      setPassword('');
      if (r.mfa_required && r.mfa_token) { setTicket(r.mfa_token); setCode(''); } else onSignedIn();
    }
    catch (caught) { const m = (caught as Error).message; setError(m); if (/took too long/.test(m)) setTicket(null); }
    finally { setBusy(false); }
  }

  return (
    <main className="login">
      <section className="login-art">
        <div className="brand"><Logo size={36} />{company}</div>
        <div>
          <h1>Know before <em>they know.</em></h1>
          <p>Uptime, host metrics, incidents and alerts for every server and service, in one place.</p>
        </div>
        <small className="muted">Install an agent on any server in one command.</small>
      </section>
      <form className="login-form" onSubmit={submit}>
        {ticket ? <>
          <div><h2>Two-factor sign-in</h2><p className="muted">Enter the 6-digit code from your authenticator app for {email}.</p></div>
          <label className="field">Code<input value={code} onChange={e => setCode(e.target.value.trim().slice(0, 20))} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" required autoFocus /></label>
          <small className="muted">Lost your phone? Enter one of your recovery codes instead.</small>
          {error && <div className="err" role="alert">{error}</div>}
          <button className="btn primary" disabled={busy || code.length < 6}>{busy ? 'Checking…' : 'Verify'}</button>
          <button type="button" className="btn ghost" onClick={() => { setTicket(null); setError(''); }}>Back</button>
        </> : <>
        <div><h2>Welcome back</h2><p className="muted">Sign in to the control plane.</p></div>
        <label className="field">Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} autoComplete="username" required autoFocus /></label>
        <label className="field">Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        {error && <div className="err" role="alert">{error}</div>}
        <button className="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </>}
        <a className="sm muted" href="/status">View public status page →</a>
      </form>
    </main>
  );
}
