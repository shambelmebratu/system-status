'use client';

import { FormEvent, useState } from 'react';
import { Field } from '../components/ui';
import { post } from '../lib/api';
import type { Me } from '../lib/types';

/** Shown instead of the app while the account still has a temporary password. */
export function ForcePasswordChange({ company, me, onDone, onSignOut }: { company: string; me: Me; onDone: () => void; onSignOut: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    if (next !== again) { setError('The two new passwords do not match'); return; }
    setBusy(true);
    try { await post('/auth/password', { current_password: current, new_password: next }); onDone(); }
    catch (caught) { setError((caught as Error).message); } finally { setBusy(false); }
  }

  return (
    <main className="login">
      <section className="login-art">
        <div className="brand"><span className="logo">★</span>{company}</div>
        <div><h1>One last <em>step.</em></h1><p>An administrator set a temporary password for your account. Choose your own before you continue.</p></div>
        <small className="muted">Signed in as {me.email}</small>
      </section>
      <form className="login-form" onSubmit={submit}>
        <div><h2>Choose a new password</h2><p className="muted">At least 12 characters. It signs you out of any other sessions.</p></div>
        <Field label="Temporary password"><input type="password" value={current} onChange={e => setCurrent(e.target.value)} autoComplete="current-password" required autoFocus /></Field>
        <Field label="New password"><input type="password" value={next} onChange={e => setNext(e.target.value)} minLength={12} autoComplete="new-password" required /></Field>
        <Field label="Repeat new password"><input type="password" value={again} onChange={e => setAgain(e.target.value)} minLength={12} autoComplete="new-password" required /></Field>
        {error && <div className="err" role="alert">{error}</div>}
        <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save and continue'}</button>
        <button type="button" className="btn ghost" onClick={onSignOut}>Sign out</button>
      </form>
    </main>
  );
}
