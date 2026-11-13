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
    api<{ public_url?: string }>('/branding').then(b => b.public_url && setBase(b.public_url)).catch(() => undefined);
  }, []);
  return [base, setBase] as const;
}

export const joinCommands = (base: string, token: string) => ({
  shell: `curl -fsSL ${base}/api/agent/join/${token} | sudo bash`,
  docker: `curl -fsSL ${base}/api/agent/join/${token}/docker | sudo bash`,
});

export function expiryText(e: Enrollment): string {
  if (e.state !== 'active') return e.state;
  if (!e.expires_at) return 'never expires';
  const hours = Math.max(0, (new Date(e.expires_at).getTime() - Date.now()) / 3600000);
  return hours < 1 ? `expires in ${Math.max(1, Math.round(hours * 60))} min` : hours < 48 ? `expires in ${Math.round(hours)} h` : `expires in ${Math.round(hours / 24)} days`;
}

/** Shell / Docker one-liners for a join token. */
export function JoinCommands({ token, base }: { token: string; base: string }) {
  const [tab, setTab] = useState<'shell' | 'docker'>('shell');
  const cmd = joinCommands(base, token);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="seg" style={{ alignSelf: 'flex-start' }}>
        <button className={tab === 'shell' ? 'on' : ''} onClick={() => setTab('shell')}>Linux shell</button>
        <button className={tab === 'docker' ? 'on' : ''} onClick={() => setTab('docker')}>Docker</button>
      </div>
      <CodeBox value={cmd[tab]} />
      <span className="sm muted">{tab === 'shell' ? 'Run as a sudo user on the server. Installs a small systemd service; installs python3/curl first if missing.' : 'Needs only Docker on the server: no repo and no image build.'}</span>
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
    /** Creates a fresh link (valid 15 minutes) on demand. */
    generate: async (label = 'Dashboard') => {
      setBusy(true);
      try { await post('/enrollments', { label, expires_minutes: 15 }); await load(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    },
    revoke: async (id: number) => { await del(`/enrollments/${id}`); await load(); },
  };
}

export { timeAgo };
