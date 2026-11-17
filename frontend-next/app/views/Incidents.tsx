'use client';

import { useMemo, useState } from 'react';
import { Empty, Icon } from '../components/ui';
import { api } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { duration, timeAgo } from '../lib/format';
import type { Incident } from '../lib/types';
import { IncidentAi } from '../components/ai';

type State = 'open' | 'resolved' | 'all';
type Kind = 'all' | Incident['target_type'];
const KIND_LABEL: Record<Incident['target_type'], string> = { server: 'Server', service: 'Service', cluster: 'Cluster', test: 'API test', dns: 'Domain', heartbeat: 'Cron job' };
const KIND_ICON: Record<Incident['target_type'], string> = { server: 'server', service: 'globe', cluster: 'k8s', test: 'check', dns: 'globe', heartbeat: 'clock' };

/** "web-01 is over its resource thresholds" -> "Over a resource limit": the name is shown separately. */
function what(i: Incident): string {
  const t = i.title.toLowerCase();
  if (t.endsWith('is down')) return i.target_type === 'service' ? 'Not responding' : 'Down';
  if (t.includes('resource thresholds')) return 'Over a resource limit';
  if (t.includes('has problems')) return 'Cluster problems';
  return i.title.replace(i.target_name, '').trim() || i.title;
}
const reasons = (detail: string | null, split: boolean) => (detail ?? '').split(split ? /\n|;\s+/ : /\n/).map(x => x.trim().replace(/\bPID (\d+)/, '(PID $1)').replace(' >= ', ' ≥ ')).filter(Boolean);
const dayKey = (iso: string) => new Date(iso).toDateString();
function dayLabel(iso: string): string {
  const d = new Date(iso), today = new Date(), yesterday = new Date(Date.now() - 86400000);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long', year: d.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
}
const clockTime = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export function Incidents() {
  const { go } = useApp();
  const [state, setState] = useState<State>('all');
  const [kind, setKind] = useState<Kind>('all');
  const [q, setQ] = useState('');
  const { value, error, reload } = usePoll(() => api<Incident[]>('/incidents?state=all&limit=500'), [], 15000, true);

  const stats = useMemo(() => {
    const all = value ?? [];
    const weekAgo = Date.now() - 7 * 86400000;
    const open = all.filter(i => !i.resolved_at);
    const week = all.filter(i => new Date(i.started_at).getTime() >= weekAgo);
    const resolvedWeek = week.filter(i => i.resolved_at);
    const mttr = resolvedWeek.length ? Math.round(resolvedWeek.reduce((n, i) => n + i.duration_seconds, 0) / resolvedWeek.length) : null;
    const counts = new Map<string, number>();
    for (const i of week) counts.set(i.target_name, (counts.get(i.target_name) ?? 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
    return { open, week, mttr, top, critical: open.filter(i => i.severity === 'critical').length };
  }, [value]);

  const shown = useMemo(() => (value ?? []).filter(i =>
    (state === 'all' || (state === 'open') === !i.resolved_at)
    && (kind === 'all' || i.target_type === kind)
    && (!q || `${i.target_name} ${i.title} ${i.detail ?? ''}`.toLowerCase().includes(q.toLowerCase()))), [value, state, kind, q]);
  const groups = useMemo(() => {
    const out: { key: string; label: string; items: Incident[] }[] = [];
    for (const i of shown) {
      const key = dayKey(i.started_at);
      const last = out[out.length - 1];
      if (last && last.key === key) last.items.push(i); else out.push({ key, label: dayLabel(i.started_at), items: [i] });
    }
    return out;
  }, [shown]);
  const kinds = useMemo(() => [...new Set((value ?? []).map(i => i.target_type))], [value]);
  const open = (i: Incident) => go({ cluster: `kubernetes/${i.target_id}`, test: `tests/${i.target_id}`, dns: 'dns', heartbeat: 'heartbeats', server: `servers/${i.target_id}`, service: `services/${i.target_id}` }[i.target_type]);

  return (
    <>
      <div className="topbar"><div><h1>Incidents</h1><p className="muted sm">Opened automatically when a monitor fails, closed when it recovers.</p></div></div>

      <div className="kpis" style={{ marginBottom: 16 }}>
        <div className={`kpi ${stats.open.length ? (stats.critical ? 'bad' : 'warn') : 'good'}`}>
          <div className="kpi-head"><span className="kpi-ico"><Icon name={stats.open.length ? 'alert' : 'check'} size={16} /></span><span className="kpi-label">Open now</span></div>
          <div className="kpi-value">{stats.open.length}</div><div className="kpi-sub">{stats.open.length ? `${stats.critical} critical · ${stats.open.length - stats.critical} warning` : 'everything is healthy'}</div>
        </div>
        <div className="kpi"><div className="kpi-head"><span className="kpi-ico"><Icon name="clock" size={16} /></span><span className="kpi-label">Last 7 days</span></div>
          <div className="kpi-value">{stats.week.length}</div><div className="kpi-sub">incident{stats.week.length === 1 ? '' : 's'} started</div></div>
        <div className="kpi"><div className="kpi-head"><span className="kpi-ico"><Icon name="refresh" size={16} /></span><span className="kpi-label">Time to recover</span></div>
          <div className="kpi-value">{stats.mttr != null ? duration(stats.mttr) : '–'}</div><div className="kpi-sub">average, last 7 days</div></div>
        <div className="kpi"><div className="kpi-head"><span className="kpi-ico"><Icon name="server" size={16} /></span><span className="kpi-label">Most affected</span></div>
          <div className="kpi-value trunc" style={{ fontSize: 18, lineHeight: '29px' }} title={stats.top?.[0]}>{stats.top ? stats.top[0] : '–'}</div><div className="kpi-sub">{stats.top ? `${stats.top[1]} incident${stats.top[1] === 1 ? '' : 's'} in 7 days` : 'no incidents in 7 days'}</div></div>
      </div>

      <div className="inc-bar">
        <div className="seg">{([['all', 'All'], ['open', `Open${stats.open.length ? ` (${stats.open.length})` : ''}`], ['resolved', 'Resolved']] as [State, string][]).map(([id, label]) => <button key={id} className={state === id ? 'on' : ''} onClick={() => setState(id)}>{label}</button>)}</div>
        {kinds.length > 1 && <div className="seg">{(['all', ...kinds] as Kind[]).map(k => <button key={k} className={kind === k ? 'on' : ''} onClick={() => setKind(k)}>{k === 'all' ? 'Everything' : `${KIND_LABEL[k]}s`}</button>)}</div>}
        <span className="grow" />
        <input className="inc-search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search name or reason…" aria-label="Search incidents" />
      </div>

      {error && !value ? <div className="err">{error}</div> : !value ? <p className="muted">Loading…</p> : shown.length === 0 ? (
        <div className="card"><Empty title={value.length === 0 ? 'No incidents yet' : state === 'open' ? 'No open incidents' : 'Nothing matches'}>{value.length === 0 ? 'Incidents open automatically when a monitor fails and resolve when it recovers.' : state === 'open' ? 'Everything is healthy right now.' : 'Try another filter or search term.'}</Empty></div>
      ) : groups.map(group => (
        <section key={group.key} className="inc-group">
          <h2 className="inc-day">{group.label}<span>{group.items.length}</span></h2>
          <div className="inc-list">
            {group.items.map(i => {
              const ongoing = !i.resolved_at;
              const lines = reasons(i.detail, i.target_type !== 'service');   // a service has one error sentence; servers and clusters list several
              return (
                <article key={i.id} className={`inc ${ongoing ? i.severity : 'resolved'}`} onClick={() => open(i)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && open(i)}>
                  <span className="inc-ico"><Icon name={ongoing ? 'alert' : 'check'} size={18} /></span>
                  <div className="inc-main">
                    <div className="inc-title"><b>{i.target_name}</b><span className="tag"><Icon name={KIND_ICON[i.target_type]} size={11} /> {KIND_LABEL[i.target_type]}</span>{ongoing && <span className={`inc-sev ${i.severity}`}>{i.severity === 'critical' ? 'Critical' : 'Warning'}</span>}</div>
                    <div className="inc-what">{what(i)}</div>
                    {lines.length > 0 && <ul className="inc-reasons">{lines.slice(0, 3).map((l, n) => <li key={n}>{l}</li>)}{lines.length > 3 && <li className="muted">+ {lines.length - 3} more</li>}</ul>}
                    <IncidentAi incidentId={i.id} analysis={i.ai_analysis ?? null} model={i.ai_model ?? null} generatedAt={i.ai_generated_at ?? null} onDone={() => void reload()} />
                  </div>
                  <div className="inc-side">
                    <span className={`inc-state ${ongoing ? i.severity : 'resolved'}`}><i />{ongoing ? 'Ongoing' : 'Resolved'}</span>
                    <b className="inc-dur" title={ongoing ? 'So far' : 'How long it lasted'}>{duration(i.duration_seconds)}</b>
                    <span className="inc-time" title={new Date(i.started_at).toLocaleString()}>{clockTime(i.started_at)}{i.resolved_at ? ` → ${clockTime(i.resolved_at)}` : ` · ${timeAgo(i.started_at)}`}</span>
                  </div>
                </article>);
            })}
          </div>
        </section>))}
    </>
  );
}
