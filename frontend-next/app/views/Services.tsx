'use client';

import { FormEvent, useState } from 'react';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { AvailabilityPanel } from '../components/availability';
import { AreaChart } from '../components/charts';
import { Empty, Field, Icon, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { clock, ms, pct, timeAgo, uptimeClass } from '../lib/format';
import type { Range, Service, ServiceHistory } from '../lib/types';

export function Services() {
  const { data, route, go, canOperate } = useApp();
  if (!data) return <p className="muted">Loading…</p>;
  if (route[1] === 'new' && canOperate) return <><ServiceList /><ServiceForm onClose={() => go('services')} /></>;
  if (route[1]) {
    const service = data.services.find(s => s.id === Number(route[1]));
    return service ? <ServiceDetail service={service} /> : <Empty title="Service not found" action={<button className="btn" onClick={() => go('services')}>Back to services</button>} />;
  }
  return <ServiceList />;
}

function ServiceList() {
  const { data, go, canOperate } = useApp();
  const services = data!.services;
  return (
    <>
      <div className="topbar"><h1>Services</h1><span className="grow" />{canOperate && <button className="btn primary" onClick={() => go('services/new')}><Icon name="plus" size={15} />Add service</button>}</div>
      <div className="card">
        {services.length === 0 ? <Empty title="No services yet" action={canOperate ? <button className="btn primary" onClick={() => go('services/new')}>Add a website or API</button> : undefined}>Monitor any HTTP(S) endpoint for availability and response time.</Empty> : (
          <table className="tbl"><thead><tr><th>Service</th><th>Status</th><th className="num hide-sm">HTTP</th><th className="num hide-sm">Response</th><th className="num">Uptime 24h</th><th className="hide-sm">Checked</th></tr></thead>
            <tbody>{services.map(s => (
              <tr key={s.id} className="link" onClick={() => go(`services/${s.id}`)}>
                <td><div className="name">{s.name}{s.public && <> <span className="tag">public</span></>}<small>{s.url}</small></div></td>
                <td><StatusPill status={s.last_status} /></td><td className="num hide-sm">{s.last_http_status ?? '–'}</td>
                <td className="num hide-sm">{ms(s.last_latency_ms)}</td><td className={`num ${uptimeClass(s.uptime_24h)}`}>{pct(s.uptime_24h, 2)}</td><td className="hide-sm muted">{timeAgo(s.last_checked_at)}</td>
              </tr>))}</tbody></table>
        )}
      </div>
    </>
  );
}

function ServiceDetail({ service }: { service: Service }) {
  const { go, toast, refresh, canOperate, confirm } = useApp();
  const [range, setRange] = useState<Range>('24h');
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const history = usePoll(() => api<ServiceHistory>(`/services/${service.id}/history?range=${range}`), [service.id, range], 20000);
  const uptime = usePoll(() => api<Record<string, Record<string, number>>>('/uptime'), [], 60000).value?.[`service:${service.id}`];
  const h = history.value;

  async function checkNow() {
    setBusy(true);
    try {
      const r = await post<{ status: string; http_status: number | null; latency_ms: number; error: string | null }>(`/services/${service.id}/check`);
      toast(`${r.status.toUpperCase()} · HTTP ${r.http_status ?? 'no response'} · ${r.latency_ms} ms`, r.status !== 'up');
      await refresh(); await history.reload();
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  async function remove() {
    if (!(await confirm(`Remove ${service.name}?\n\nIts history is deleted too. This cannot be undone.`))) return;
    try { await del(`/services/${service.id}`); toast('Service removed'); await refresh(); go('services'); } catch (e) { toast((e as Error).message, true); }
  }

  return (
    <>
      <div className="topbar">
        <button className="btn ghost sm" onClick={() => go('services')}><Icon name="back" size={15} />Services</button>
        <h1>{service.name}</h1><StatusPill status={service.last_status} /><span className="grow" />
        {canOperate && <button className="btn sm" onClick={checkNow} disabled={busy}><Icon name="refresh" size={14} />{busy ? 'Checking…' : 'Check now'}</button>}
        {canOperate && <button className="btn sm" onClick={() => setEditing(true)}>Edit</button>}
        {canOperate && <button className="btn sm danger" onClick={remove}>Remove</button>}
      </div>
      <p className="muted" style={{ marginTop: -12, marginBottom: 18 }}><a href={service.url} target="_blank" rel="noreferrer noopener">{service.url}</a> · expects HTTP {service.expected_status} · every {service.interval_seconds}s</p>
      {service.last_status === 'down' && service.last_error && <div className="err" style={{ marginBottom: 16 }}>{service.last_error}</div>}

      <div className="grid g4">
        <div className="card stat"><span className="label">Response now</span><span className="value">{ms(service.last_latency_ms)}</span><span className="sub">HTTP {service.last_http_status ?? '–'} · {timeAgo(service.last_checked_at)}</span></div>
        <div className="card stat"><span className="label">Uptime 24h</span><span className={`value ${uptimeClass(uptime?.['24h'])}`}>{pct(uptime?.['24h'], 2)}</span></div>
        <div className="card stat"><span className="label">Uptime 7d / 30d</span><span className="value" style={{ fontSize: 22 }}>{pct(uptime?.['7d'], 2)} <span className="muted">/</span> {pct(uptime?.['30d'], 2)}</span></div>
        <div className="card stat"><span className="label">Latency avg · p95</span><span className="value" style={{ fontSize: 22 }}>{ms(h?.latency_avg)} <span className="muted">·</span> {ms(h?.latency_p95)}</span><span className="sub">max {ms(h?.latency_max)}</span></div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '20px 0 12px' }}>
        <div className="seg">{(['1h', '6h', '24h', '7d', '30d'] as Range[]).map(r => <button key={r} className={range === r ? 'on' : ''} onClick={() => setRange(r)}>{r}</button>)}</div>
        {h && <span className="muted sm">{h.checks} checks</span>}
      </div>
      <div className="grid">
        <section className="card"><div className="card-head"><h2>Response time</h2></div>
          <AreaChart points={h?.points ?? []} height={200} showDate={range === '7d' || range === '30d'} series={[{ key: 'latency', label: 'Latency', color: 'var(--accent)', format: v => `${Math.round(v)} ms` }]} unit="ms" /></section>
        <AvailabilityPanel kind="services" id={service.id} />
        <section className="card"><div className="card-head"><h2>Recent failures</h2></div>
          {h?.recent_failures.length ? <table className="tbl"><tbody>{[...h.recent_failures].reverse().map(f => <tr key={f.t}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{clock(f.t, true)}</td><td className="bad">{f.http_status ? `HTTP ${f.http_status}` : 'No response'}</td><td className="sm mono">{f.error}</td></tr>)}</tbody></table> : <p className="muted sm">No failed checks in this range.</p>}
        </section>
      </div>
      {editing && <ServiceForm existing={service} onClose={() => setEditing(false)} />}
    </>
  );
}

function ServiceForm({ existing, onClose }: { existing?: Service; onClose: () => void }) {
  const { toast, refresh } = useApp();
  const [name, setName] = useState(existing?.name ?? '');
  const [url, setUrl] = useState(existing?.url ?? 'https://');
  const [expected, setExpected] = useState(String(existing?.expected_status ?? 200));
  const [interval, setIntervalValue] = useState(String(existing?.interval_seconds ?? 60));
  const [isPublic, setPublic] = useState(existing?.public ?? false);
  const [alerts, setAlerts] = useState<MonitorAlerts>(alertsOf(existing));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    const body = { name, url, expected_status: Number(expected), interval_seconds: Number(interval), public: isPublic, ...alerts };
    try {
      if (existing) await put(`/services/${existing.id}`, body); else await post('/services', body);
      toast(existing ? 'Service updated' : 'Service added'); await refresh(); onClose();
    } catch (caught) { setError((caught as Error).message); } finally { setBusy(false); }
  }

  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'Add a service'} onClose={onClose}>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="form-grid">
          <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder="Marketing site" required autoFocus /></Field>
          <Field label="URL"><input type="url" value={url} onChange={e => setUrl(e.target.value)} required /></Field>
          <Field label="Expected HTTP status"><input type="number" min={100} max={599} value={expected} onChange={e => setExpected(e.target.value)} required /></Field>
          <Field label="Interval (seconds)"><input type="number" min={15} max={86400} value={interval} onChange={e => setIntervalValue(e.target.value)} required /></Field>
        </div>
        <MonitorAlertSettings kind="service" value={alerts} onChange={setAlerts} />
        <label className="check"><input type="checkbox" checked={isPublic} onChange={e => setPublic(e.target.checked)} />Show on the public status page <span className="muted">(name and uptime only; the URL stays private)</span></label>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>
      </form>
    </Modal>
  );
}
