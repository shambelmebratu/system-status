'use client';

import { Logo } from '../components/logo';
import { useEffect, useState } from 'react';
import { UptimeBar } from '../components/charts';
import { StatusPill } from '../components/ui';
import { api } from '../lib/api';
import { duration, pct, timeAgo } from '../lib/format';
import type { Daily } from '../lib/types';

type PublicStatus = {
  company_name: string; overall: 'up' | 'down' | 'alert' | 'unknown'; updated_at: string;
  services: { id: string; kind: string; name: string; status: string; latency_ms: number | null; uptime_90d: number | null; daily: Daily[] }[];
  incidents: { id: number; target_name: string; title: string; severity: string; started_at: string; resolved_at: string | null; duration_seconds: number }[];
};

export default function StatusPage() {
  const [data, setData] = useState<PublicStatus | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const load = () => api<PublicStatus>('/public/status').then(d => { setData(d); setError(''); document.title = `${d.company_name} Status`; }).catch(e => setError((e as Error).message));
    load();
    const timer = setInterval(load, 30000);
    return () => clearInterval(timer);
  }, []);

  if (error) return <main className="public"><div className="card"><h2>Status unavailable</h2><p className="muted">{error}</p></div></main>;
  if (!data) return null;
  const headline = { up: 'All systems operational', alert: 'Some systems are degraded', down: 'Some systems are experiencing issues', unknown: 'No status information yet' }[data.overall];
  return (
    <main className="public">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}><Logo size={38} /><h1 style={{ fontSize: 26 }}>{data.company_name} Status</h1></div>
      <div className={`banner-big ${data.overall === 'alert' ? 'down' : data.overall}`}><span style={{ color: data.overall === 'up' ? 'var(--good)' : data.overall === 'down' ? 'var(--bad)' : data.overall === 'alert' ? 'var(--warn)' : 'var(--muted)' }}>{data.overall === 'up' ? '✓' : data.overall === 'unknown' ? '…' : '!'}</span>{headline}</div>
      {data.services.map(s => (
        <section key={s.id} className="card pub-svc">
          <div className="row"><span className="grow">{s.name}</span><span className="muted sm">{pct(s.uptime_90d, 2)} uptime</span><StatusPill status={s.status} /></div>
          <UptimeBar days={s.daily} />
        </section>
      ))}
      {data.services.length === 0 && <div className="card muted">Nothing is published here yet. Enable “Show on the public status page” on a server or service.</div>}
      <section className="card">
        <div className="card-head"><h2>Past 30 days</h2></div>
        {data.incidents.length === 0 ? <p className="muted sm">No incidents reported.</p> : (
          <div className="timeline">{data.incidents.map(i => (
            <div key={i.id} className="tl-item"><span className={`tl-dot ${i.resolved_at ? 'resolved' : i.severity}`} />
              <div className="tl-body"><b>{i.title}</b><div className="tl-meta">{i.resolved_at ? `Resolved after ${duration(i.duration_seconds)}` : 'Ongoing'} · {timeAgo(i.started_at)}</div></div></div>))}</div>
        )}
      </section>
      <p className="muted sm" style={{ textAlign: 'center' }}>Updated {timeAgo(data.updated_at)} · refreshes automatically</p>
    </main>
  );
}
