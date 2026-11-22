'use client';

import { Fragment } from 'react';
import { Empty, Icon, Meter } from '../components/ui';
import { MonitorStatus } from '../components/pause';
import { post } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { api } from '../lib/api';
import { duration, ms, pct, timeAgo } from '../lib/format';
import type { Incident } from '../lib/types';

export function Overview() {
  const { data, go, toast, refresh, canOperate } = useApp();
  const incidents = usePoll(() => api<Incident[]>('/incidents?limit=8'), [], 20000);
  if (!data) return <p className="muted">Loading…</p>;

  const { servers, services, summary } = data;
  const all = [...servers, ...services];
  const down = all.filter(t => t.last_status === 'down').length;
  const alert = all.filter(t => t.last_status === 'alert').length;
  const state = all.length === 0 ? 'unknown' : down ? 'down' : alert ? 'alert' : 'up';
  const headline = { unknown: 'Nothing monitored yet', down: `${down} ${down === 1 ? 'target is' : 'targets are'} down`, alert: `${alert} ${alert === 1 ? 'target needs' : 'targets need'} attention`, up: 'All systems operational' }[state];
  const uptimes = all.map(t => t.uptime_24h).filter((v): v is number => v != null);
  const avgUptime = uptimes.length ? uptimes.reduce((a, b) => a + b, 0) / uptimes.length : null;
  const latencies = services.map(s => s.last_latency_ms).filter((v): v is number => v != null);
  const avgLatency = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null;
  const online = servers.filter(s => s.last_status === 'up' || s.last_status === 'alert').length;
  const metricServers = servers.filter(s => s.last_metrics?.cpu != null);
  const avg = (key: 'cpu' | 'memory') => (metricServers.length ? metricServers.reduce((a, s) => a + (s.last_metrics?.[key] ?? 0), 0) / metricServers.length : undefined);

  if (all.length === 0) {
    return (
      <>
        <div className="topbar"><h1>Overview</h1></div>
        <div className="card"><Empty title={canOperate ? 'Let’s add your first monitor' : 'Nothing is monitored yet'} action={!canOperate ? undefined : <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn primary" onClick={() => go('servers/new')}><Icon name="plus" />Add a server</button>
          <button className="btn" onClick={() => go('services/new')}><Icon name="globe" />Add a website / API</button></div>}>
          Install the agent on a server for CPU, memory, disk and network metrics, or point a monitor at any URL.
        </Empty></div>
      </>
    );
  }

  return (
    <>
      <div className="topbar">
        <h1>Overview</h1><span className="grow" />
        {canOperate && <button className="btn" onClick={async () => { try { await post('/monitor/run'); toast('Checks queued'); setTimeout(() => void refresh(), 2500); } catch (e) { toast((e as Error).message, true); } }}><Icon name="refresh" size={15} />Run checks now</button>}
      </div>

      <div className="hero">
        <div className="card"><div className={`health ${state}`}><div className="dot">{state === 'up' ? '✓' : state === 'unknown' ? '…' : '!'}</div><div><h2>{headline}</h2><p className="muted">{servers.length} servers · {services.length} services · {summary.open_incidents} open incidents</p></div></div></div>
        <div className="card stat"><span className="label">Availability · 24h</span><span className="value">{pct(avgUptime, 2)}</span><span className="sub">across all monitors</span></div>
        <div className="card stat"><span className="label">Servers online</span><span className="value">{online}<small className="muted" style={{ fontSize: 16 }}> / {servers.length}</small></span><span className="sub">{avg('cpu') != null ? `Avg CPU ${pct(avg('cpu'), 0)} · Mem ${pct(avg('memory'), 0)}` : 'no agent metrics yet'}</span></div>
        <div className="card stat"><span className="label">Avg response</span><span className="value">{ms(avgLatency)}</span><span className="sub">{services.filter(s => s.last_status === 'up').length}/{services.length} services up</span></div>
      </div>

      <div className="grid g-side" style={{ marginTop: 16 }}>
        <div className="grid">
          <section className="card">
            <div className="card-head"><h2>Servers</h2><span className="grow" /><button className="btn sm ghost" onClick={() => go('servers')}>View all</button></div>
            {servers.length === 0 ? <Empty title="No servers"><button className="btn primary" onClick={() => go('servers/new')}>Add server</button></Empty> : (
              <table className="tbl"><thead><tr><th>Server</th><th>Status</th><th className="hide-sm">CPU</th><th className="hide-sm">Memory</th><th className="hide-sm">Disk</th><th className="num">24h</th></tr></thead>
                <tbody>{servers.map(s => {
                  const m = s.last_metrics;
                  return <tr key={s.id} className="link" onClick={() => go(`servers/${s.id}`)}>
                    <td><div className="name">{s.name}<small>{m?.hostname || s.host || 'awaiting first report'}</small></div></td>
                    <td><MonitorStatus item={s} /></td>
                    {(['cpu', 'memory', 'disk'] as const).map(k => <td key={k} className="hide-sm" style={{ minWidth: 90 }}>{m?.[k] != null ? <Fragment><span className="sm">{pct(m[k], 0)}</span><Meter value={m[k]!} warnAt={(s[`${k}_threshold` as const] as number) * 0.85} badAt={s[`${k}_threshold` as const] as number} /></Fragment> : <span className="muted">–</span>}</td>)}
                    <td className="num">{pct(s.uptime_24h, 2)}</td></tr>;
                })}</tbody></table>
            )}
          </section>
          <section className="card">
            <div className="card-head"><h2>Services</h2><span className="grow" /><button className="btn sm ghost" onClick={() => go('services')}>View all</button></div>
            {services.length === 0 ? <Empty title="No services"><button className="btn primary" onClick={() => go('services/new')}>Add service</button></Empty> : (
              <table className="tbl"><thead><tr><th>Service</th><th>Status</th><th className="num hide-sm">Response</th><th className="num">24h</th></tr></thead>
                <tbody>{services.map(s => <tr key={s.id} className="link" onClick={() => go(`services/${s.id}`)}>
                  <td><div className="name">{s.name}<small>{s.url}</small></div></td><td><MonitorStatus item={s} /></td>
                  <td className="num hide-sm">{ms(s.last_latency_ms)}</td><td className="num">{pct(s.uptime_24h, 2)}</td></tr>)}</tbody></table>
            )}
          </section>
        </div>
        <section className="card">
          <div className="card-head"><h2>Recent incidents</h2><span className="grow" /><button className="btn sm ghost" onClick={() => go('incidents')}>All</button></div>
          {!incidents.value?.length ? <Empty title="No incidents">Nothing has gone wrong yet.</Empty> : <IncidentList items={incidents.value} />}
        </section>
      </div>
    </>
  );
}

export function IncidentList({ items, onSelect }: { items: Incident[]; onSelect?: (i: Incident) => void }) {
  const { go } = useApp();
  return (
    <div className="timeline">
      {items.map(i => (
        <div key={i.id} className="tl-item" style={{ cursor: 'pointer' }} onClick={() => (onSelect ? onSelect(i) : go(i.target_type === 'cluster' ? `kubernetes/${i.target_id}` : `${i.target_type}s/${i.target_id}`))}>
          <span className={`tl-dot ${i.resolved_at ? 'resolved' : i.severity}`} />
          <div className="tl-body">
            <b>{i.title}</b>
            <div className="tl-meta">{i.resolved_at ? `Resolved · lasted ${duration(i.duration_seconds)}` : <span className={i.severity === 'critical' ? 'bad' : 'warn'}>Ongoing for {duration(i.duration_seconds)}</span>} · started {timeAgo(i.started_at)}</div>
            {i.detail && <div className="tl-meta mono" style={{ marginTop: 3 }}>{i.detail}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}
