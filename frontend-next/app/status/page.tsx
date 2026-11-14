'use client';

import { Logo } from '../components/logo';
import { useCallback, useEffect, useState } from 'react';
import { UptimeBar } from '../components/charts';
import { StatusPill } from '../components/ui';
import { api } from '../lib/api';
import { duration, pct, timeAgo } from '../lib/format';
import type { Daily } from '../lib/types';

type PublicStatus = {
  company_name: string; overall: 'up' | 'down' | 'alert' | 'unknown'; updated_at: string; days: number; ranges: number[];
  services: { id: string; kind: string; name: string; status: string; latency_ms: number | null; uptime: number | null; daily: Daily[] }[];
  incidents: { id: number; target_name: string; title: string; severity: string; started_at: string; resolved_at: string | null; duration_seconds: number }[];
};

export default function StatusPage() {
  const [data, setData] = useState<PublicStatus | null>(null);
  const [error, setError] = useState('');
  const [days, setDays] = useState<number | null>(null);   // null = the default configured on the server (PUBLIC_STATUS_DEFAULT_DAYS)
  useEffect(() => {
    const asked = Number(new URLSearchParams(window.location.search).get('days'));
    if (asked > 0) setDays(asked);   // a shared link such as /status?days=7 opens on that time frame
  }, []);
  const load = useCallback(() => api<PublicStatus>(`/public/status${days ? `?days=${days}` : ''}`).then(d => { setData(d); setError(''); document.title = `${d.company_name} Status`; })
    .catch(e => { if (days) { setDays(null); window.history.replaceState(null, '', window.location.pathname); } else setError((e as Error).message); }), [days]);
  useEffect(() => {
    void load();
    const timer = setInterval(() => { if (!document.hidden) void load(); }, 30000);
    return () => clearInterval(timer);
  }, [load]);
  const choose = (d: number) => { setDays(d); window.history.replaceState(null, '', `${window.location.pathname}?days=${d}`); };

  if (error) return <main className="public"><div className="card"><h2>Status unavailable</h2><p className="muted">{error}</p></div></main>;
  if (!data) return null;
  const headline = { up: 'All systems operational', alert: 'Some systems are degraded', down: 'Some systems are experiencing issues', unknown: 'No status information yet' }[data.overall];
  return (
    <main className="public">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}><Logo size={38} /><h1 style={{ fontSize: 26 }}>{data.company_name} Status</h1><span style={{ flex: 1 }} />
        {data.ranges.length > 1 && <div className="seg" role="group" aria-label="Time frame">{data.ranges.map(r => <button key={r} className={data.days === r ? 'on' : ''} onClick={() => choose(r)} aria-pressed={data.days === r}>{r === 1 ? '24 hours' : `${r} days`}</button>)}</div>}</div>
      <div className={`banner-big ${data.overall === 'alert' ? 'down' : data.overall}`}><span style={{ color: data.overall === 'up' ? 'var(--good)' : data.overall === 'down' ? 'var(--bad)' : data.overall === 'alert' ? 'var(--warn)' : 'var(--muted)' }}>{data.overall === 'up' ? '✓' : data.overall === 'unknown' ? '…' : '!'}</span>{headline}</div>
      {data.services.map(s => (
        <section key={s.id} className="card pub-svc">
          <div className="row"><span className="grow">{s.name}</span><span className="muted sm">{pct(s.uptime, 2)} uptime · {data.days} days</span><StatusPill status={s.status} /></div>
          <UptimeBar days={s.daily} />
        </section>
      ))}
      {data.services.length === 0 && <div className="card muted">Nothing is published here yet. Enable “Show on the public status page” on a server or service.</div>}
      <section className="card">
        <div className="card-head"><h2>Past {data.days} days</h2></div>
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
