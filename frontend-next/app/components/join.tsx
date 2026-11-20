'use client';

import { useEffect, useState } from 'react';
import { api, del, post } from '../lib/api';
import { timeAgo } from '../lib/format';
import type { Enrollment } from '../lib/types';
import { CodeBox } from './ui';

/** The control-plane address agents should use: PUBLIC_URL when configured, otherwise the address this browser used. */
export function useControlPlaneUrl() {
  const [base, setBase] = useState('');
  useEffect(() => {
    setBase(window.location.origin);
    api<{ public_url?: string }>('/branding').then(b => { if (b.public_url) { _public = b.public_url.replace(/\/$/, ''); setBase(_public); } }).catch(() => undefined);
  }, []);
  return [base, setBase] as const;
}
let _public = '';

/** The install commands. When the chosen address is not PUBLIC_URL (e.g. the LAN address), it is passed along so the agent
 *  reports to the same address it downloaded the installer from. */
export const joinCommands = (base: string, token: string, publicUrl = '') => {
  const q = publicUrl && base !== publicUrl ? `?url=${encodeURIComponent(base)}` : '';
  const url = (path: string) => (q ? `'${base}${path}${q}'` : `${base}${path}`);
  return {
    shell: `curl -fsSL ${url(`/api/agent/join/${token}`)} | sudo bash`,
    docker: `curl -fsSL ${url(`/api/agent/join/${token}/docker`)} | sudo bash`,
  };
};

/** Which address servers use to reach SM-Watch: PUBLIC_URL, the address this browser used (often the LAN one), or another. */
function AddressPicker({ base, setBase, publicUrl }: { base: string; setBase: (v: string) => void; publicUrl: string }) {
  const browser = typeof window !== 'undefined' ? window.location.origin : '';
  const options = [...new Set([publicUrl, browser].filter(Boolean))];
  const custom = !options.includes(base);
  const [editing, setEditing] = useState(custom);
  if (options.length < 2 && !editing) return <span className="sm muted">Servers reach SM-Watch at <b className="mono">{base}</b> <button type="button" className="lg-link" onClick={() => setEditing(true)}>change</button></span>;
  return (
    <div className="join-addr">
      <span className="sm muted">Servers reach SM-Watch at</span>
      <select value={editing ? '__custom' : base} onChange={e => { if (e.target.value === '__custom') setEditing(true); else { setEditing(false); setBase(e.target.value); } }} aria-label="Control-plane address">
        {options.map(o => <option key={o} value={o}>{o === publicUrl ? `${o}  (public address)` : `${o}  (this browser's address, e.g. the LAN)`}</option>)}
        <option value="__custom">Another address…</option>
      </select>
      {editing && <input className="mono" value={base} onChange={e => setBase(e.target.value.trim().replace(/\/$/, ''))} placeholder="http://192.168.1.10:8000" aria-label="Address" />}
    </div>
  );
}

export function expiryText(e: Enrollment): string {
  if (e.state !== 'active') return e.state;
  if (!e.expires_at) return 'never expires';
  const hours = Math.max(0, (new Date(e.expires_at).getTime() - Date.now()) / 3600000);
  return hours < 1 ? `expires in ${Math.max(1, Math.round(hours * 60))} min` : hours < 48 ? `expires in ${Math.round(hours)} h` : `expires in ${Math.round(hours / 24)} days`;
}

/** Shell / Docker one-liners for a join token. */
export function JoinCommands({ token, base: initial }: { token: string; base: string }) {
  const [tab, setTab] = useState<'shell' | 'docker'>('shell');
  const [base, setBase] = useState(initial);
  useEffect(() => setBase(initial), [initial]);
  const cmd = joinCommands(base, token, _public);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="seg" style={{ alignSelf: 'flex-start' }}>
        <button className={tab === 'shell' ? 'on' : ''} onClick={() => setTab('shell')}>Linux shell</button>
        <button className={tab === 'docker' ? 'on' : ''} onClick={() => setTab('docker')}>Docker</button>
      </div>
      <AddressPicker base={base} setBase={setBase} publicUrl={_public} />
      <CodeBox value={cmd[tab]} />
      <span className="sm muted">{tab === 'shell' ? 'Run as a sudo user on any Linux (Debian, Ubuntu, RHEL, CentOS, Rocky, Alma, Fedora, SUSE, Alpine…) or macOS. It installs Python 3 if needed, works without internet access, and ends by confirming the dashboard received the first report.' : 'Needs only Docker on the server: no repo and no image build.'}</span>
    </div>
  );
}

/** Lists join tokens. Nothing is created automatically: a token exists only after someone asks for one (`generate`). */
export function useActiveEnrollment() {
  const [items, setItems] = useState<Enrollment[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const load = async () => {
    try { setItems(await api<Enrollment[]>('/enrollments')); setError(''); } catch (e) { setError((e as Error).message); }
  };
  useEffect(() => { void load(); const t = setInterval(() => { if (!document.hidden) void load(); }, 10000); return () => clearInterval(t); }, []);
  const active = items?.find(i => i.active && (!i.expires_at || new Date(i.expires_at).getTime() > Date.now())) ?? null;   // newest first
  return {
    items, active, error, busy, reload: load,
    /** Creates a fresh link on demand (lifetime = ENROLLMENT_DEFAULT_MINUTES on the server). */
    generate: async (label = 'Dashboard') => {
      setBusy(true);
      try { await post('/enrollments', { label }); await load(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    },
    revoke: async (id: number) => { await del(`/enrollments/${id}`); await load(); },
  };
}

export { timeAgo };
