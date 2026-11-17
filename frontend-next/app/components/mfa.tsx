'use client';

import { FormEvent, useState } from 'react';
import { CodeBox, Field } from './ui';
import { post } from '../lib/api';

/** Two-factor setup: scan the QR code (or type the key), confirm a code, keep the recovery codes. */
export function MfaSetup({ onDone, onCancel }: { onDone: () => void; onCancel?: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr_svg: string } | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  async function start() { setBusy(true); setError(''); try { setSetup(await post('/auth/2fa/setup')); } catch (e) { setError((e as Error).message); } finally { setBusy(false); } }
  async function confirm(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { setCodes((await post<{ recovery_codes: string[] }>('/auth/2fa/enable', { code })).recovery_codes); } catch (e2) { setError((e2 as Error).message); } finally { setBusy(false); }
  }
  if (codes) return (
    <div className="mfa">
      <h3>Two-factor sign-in is on</h3>
      <p className="sm">Keep these <b>recovery codes</b> somewhere safe (a password manager). Each one signs you in once if you lose your phone. They are shown only now.</p>
      <CodeBox value={codes.join('\n')} />
      <label className="check"><input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} />I have saved my recovery codes</label>
      <button className="btn primary" disabled={!saved} onClick={onDone}>Done</button>
    </div>);
  if (!setup) return (
    <div className="mfa">
      <p className="sm">Use an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy…). After your password, you will type the 6-digit code it shows.</p>
      {error && <div className="err">{error}</div>}
      <div style={{ display: 'flex', gap: 8 }}><button className="btn primary" onClick={start} disabled={busy}>{busy ? 'Preparing…' : 'Set up two-factor sign-in'}</button>{onCancel && <button className="btn ghost" onClick={onCancel}>Cancel</button>}</div>
    </div>);
  return (
    <form className="mfa" onSubmit={confirm}>
      <div className="mfa-grid">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img className="mfa-qr" src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qr_svg)}`} alt="QR code to scan with your authenticator app" width={200} height={200} />
        <div>
          <p className="sm"><b>1.</b> Scan the code with your authenticator app.</p>
          <p className="sm muted">Cannot scan? Enter this key instead:</p>
          <code className="mfa-key">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
          <p className="sm" style={{ marginTop: 14 }}><b>2.</b> Type the 6-digit code the app shows.</p>
          <Field label="Code"><input value={code} onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" required autoFocus /></Field>
        </div>
      </div>
      {error && <div className="err">{error}</div>}
      <div style={{ display: 'flex', gap: 8 }}><button className="btn primary" disabled={busy || code.length !== 6}>{busy ? 'Checking…' : 'Turn on'}</button>{onCancel && <button type="button" className="btn ghost" onClick={onCancel}>Cancel</button>}</div>
    </form>
  );
}
