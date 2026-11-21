'use client';

import { FormEvent, useState } from 'react';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { AvailabilityPanel } from '../components/availability';
import { AreaChart } from '../components/charts';
import { ConfirmChecksField, ConfirmingBadge, Empty, Field, Icon, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { pollFor, useApp, useLimits, usePoll } from '../lib/app';
import { clock, ms, pct, timeAgo, uptimeClass } from '../lib/format';
import type { Range, Service, ServiceHistory } from '../lib/types';

export function Services() {
  const { data, route, go, canOperate, canManage } = useApp();
  if (!data) return <p className="muted">Loading…</p>;
  if (route[1] === 'new' && canManage) return <><ServiceList /><ServiceForm onClose={() => go('services')} /></>;
  if (route[1]) {
    const service = data.services.find(s => s.id === Number(route[1]));
    return service ? <ServiceDetail key={service.id} service={service} /> : <Empty title="Service not found" action={<button className="btn" onClick={() => go('services')}>Back to services</button>} />;
  }
  return <ServiceList />;
}

/** Days until the certificate expires (negative: expired), or null when unknown. */
export const certDays = (s: Service) => (s.cert_expires_at ? Math.floor((new Date(s.cert_expires_at).getTime() - Date.now()) / 86400000) : null);
function CertBadge({ service }: { service: Service }) {
  const d = certDays(service);
  if (d == null || !service.cert_check) return null;
  const warnAt = Math.max(...(service.cert_alert_days_effective ?? [30]));
  const tone = d < 0 ? 'bad' : d <= Math.min(...(service.cert_alert_days_effective ?? [7])) ? 'bad' : d <= warnAt ? 'warn' : 'good';
  return <span className={`cert-badge ${tone}`} title={`Certificate valid until ${new Date(service.cert_expires_at!).toLocaleString()}`}><Icon name="shield" size={12} />{d < 0 ? 'expired' : `${d}d`}</span>;
}

function ServiceList() {
  const { data, go, canOperate, canManage } = useApp();
  const services = data!.services;
  return (
    <>
      <div className="topbar"><h1>Services</h1><span className="grow" />{canManage && <button className="btn primary" onClick={() => go('services/new')}><Icon name="plus" size={15} />Add service</button>}</div>
      <div className="card">
        {services.length === 0 ? <Empty title="No services yet" action={canManage ? <button className="btn primary" onClick={() => go('services/new')}>Add a website or API</button> : undefined}>Monitor any HTTP(S) endpoint for availability and response time.</Empty> : (
          <table className="tbl"><thead><tr><th>Service</th><th>Status</th><th className="num hide-sm">HTTP</th><th className="num hide-sm">Response</th><th className="num">Uptime 24h</th><th className="hide-sm">Checked</th></tr></thead>
            <tbody>{services.map(s => (
              <tr key={s.id} className="link" onClick={() => go(`services/${s.id}`)}>
                <td><div className="name">{s.name}{s.public && <> <span className="tag">public</span></>} <CertBadge service={s} /><small>{s.url}</small></div></td>
                <td><StatusPill status={s.last_status} /></td><td className="num hide-sm">{s.last_http_status ?? '–'}</td>
                <td className="num hide-sm">{ms(s.last_latency_ms)}</td><td className={`num ${uptimeClass(s.uptime_24h)}`}>{pct(s.uptime_24h, 2)}</td><td className="hide-sm muted">{timeAgo(s.last_checked_at)}</td>
              </tr>))}</tbody></table>
        )}
      </div>
    </>
  );
}

function ServiceDetail({ service }: { service: Service }) {
  const { go, toast, refresh, canOperate, canManage, confirm } = useApp();
  const [range, setRange] = useState<Range>('24h');
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const history = usePoll(() => api<ServiceHistory>(`/services/${service.id}/history?range=${range}`), [service.id, range], pollFor(range), true);
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
        {canManage && <button className="btn sm danger" onClick={remove}>Remove</button>}
      </div>
      <p className="muted" style={{ marginTop: -12, marginBottom: 18 }}><a href={service.url} target="_blank" rel="noreferrer noopener">{service.url}</a> · expects HTTP {service.expected_status}{service.keyword ? ` and a page that ${service.keyword_mode === 'absent' ? 'does not contain' : 'contains'} “${service.keyword}”` : ''} · every {service.interval_seconds}s · alerts after {service.confirm_checks_effective ?? 2} failed check{service.confirm_checks_effective === 1 ? '' : 's'} in a row · times out after {service.timeout_seconds_effective ?? 10}s <ConfirmingBadge failCount={service.fail_count} needed={service.confirm_checks_effective} status={service.last_status} /></p>
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
          <AreaChart points={h?.points ?? []} height={200} showDate={range === '7d' || range === '30d'} series={[{ key: 'latency', label: 'Latency', color: 'var(--accent)', peakKey: 'latency_max', format: v => `${Math.round(v)} ms` }]} unit="ms" /></section>
        <CertificateCard service={service} />
        <AvailabilityPanel kind="services" id={service.id} />
        <section className="card"><div className="card-head"><h2>Recent failures</h2></div>
          {h?.recent_failures.length ? <table className="tbl"><tbody>{[...h.recent_failures].reverse().map(f => <tr key={f.t}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{clock(f.t, true)}</td><td className="bad">{f.http_status ? `HTTP ${f.http_status}` : 'No response'}</td><td className="sm mono">{f.error}</td></tr>)}</tbody></table> : <p className="muted sm">No failed checks in this range.</p>}
        </section>
      </div>
      {editing && <ServiceForm existing={service} onClose={() => setEditing(false)} />}
    </>
  );
}

function CertificateCard({ service }: { service: Service }) {
  const lim = useLimits();
  if (!service.url.toLowerCase().startsWith('https://')) return null;
  if (!service.cert_check) return <section className="card"><div className="card-head"><h2>Certificate</h2></div><p className="muted sm">Certificate expiry checks are off for this service (Edit to turn them on).</p></section>;
  const d = certDays(service);
  const days = service.cert_alert_days_effective ?? lim.certDays;
  const total = 90, left = d == null ? 0 : Math.max(0, Math.min(total, d));
  const tone = d == null ? 'none' : d < 0 || d <= Math.min(...days) ? 'bad' : d <= Math.max(...days) ? 'warn' : 'good';
  return (
    <section className="card">
      <div className="card-head"><h2>Certificate</h2><span className="grow" />{service.cert_checked_at && <span className="muted sm">checked {timeAgo(service.cert_checked_at)} · every {lim.certHours} h</span>}</div>
      {!service.cert_expires_at ? <p className="muted sm">{service.cert_error ? <span className="warn">{service.cert_error}</span> : 'Not read yet: it is checked with the next check (or press Check now).'}</p> : <>
        <div className="cert-top">
          <div><span className={`cert-days ${tone}`}>{d! < 0 ? 'Expired' : `${d} days`}</span><span className="muted sm">{d! < 0 ? `on ${new Date(service.cert_expires_at).toLocaleDateString()}` : `left · valid until ${new Date(service.cert_expires_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}`}</span></div>
          <div className="facts" style={{ flex: 1 }}><div><small>Issued to</small><b>{service.cert_subject ?? '–'}</b></div><div><small>Issuer</small><b>{service.cert_issuer ?? '–'}</b></div></div>
        </div>
        <div className={`cert-bar ${tone}`} title="Last 90 days before expiry"><i style={{ width: `${(left / total) * 100}%` }} />{days.filter(x => x <= total).map(x => <b key={x} style={{ left: `${(x / total) * 100}%` }} title={`Alert ${x} days before`}><span>{x}d</span></b>)}</div>
        <p className="muted sm" style={{ marginTop: 10 }}>Alerts are sent {days.map(x => `${x}`).join(', ')} days before expiry, and once more if it expires.</p>
        {service.cert_error && <p className="sm warn">{service.cert_error}</p>}
      </>}
    </section>
  );
}

function ServiceForm({ existing, onClose }: { existing?: Service; onClose: () => void }) {
  const lim = useLimits();
  const [timeout, setTimeoutValue] = useState(existing?.timeout_seconds ? String(existing.timeout_seconds) : '');
  const [certCheck, setCertCheck] = useState(existing?.cert_check ?? true);
  const [certDaysText, setCertDaysText] = useState((existing?.cert_alert_days ?? []).join(', '));
  const [keyword, setKeyword] = useState(existing?.keyword ?? '');
  const [keywordMode, setKeywordMode] = useState<'contains' | 'absent'>(existing?.keyword_mode ?? 'contains');
  const { toast, refresh } = useApp();
  const [name, setName] = useState(existing?.name ?? '');
  const [url, setUrl] = useState(existing?.url ?? 'https://');
  const [expected, setExpected] = useState(String(existing?.expected_status ?? 200));
  const [interval, setIntervalValue] = useState(String(existing?.interval_seconds ?? 60));
  const [confirmChecks, setConfirmChecks] = useState(existing?.confirm_checks ? String(existing.confirm_checks) : '');
  const [isPublic, setPublic] = useState(existing?.public ?? false);
  const [alerts, setAlerts] = useState<MonitorAlerts>(alertsOf(existing));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    const days = certDaysText.split(/[\s,]+/).filter(Boolean).map(Number);
    if (days.some(x => !Number.isInteger(x) || x < 1 || x > 365)) { setBusy(false); setError('Certificate alert days must be whole numbers between 1 and 365, e.g. 30, 14, 7'); return; }
    const body = { name, url, expected_status: Number(expected), interval_seconds: Number(interval), confirm_checks: confirmChecks ? Number(confirmChecks) : null, public: isPublic, ...alerts, timeout_seconds: timeout ? Number(timeout) : null, cert_check: certCheck, cert_alert_days: days, keyword: keyword.trim() || null, keyword_mode: keywordMode };
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
          <ConfirmChecksField value={confirmChecks} onChange={setConfirmChecks} interval={Number(interval) || 60} fallback={lim.alertAfter} />
          <Field label="Timeout (seconds)" hint={`Slower answers count as a failed check. Empty = ${lim.serviceTimeout} s (default).`}><input type="number" min={1} max={120} value={timeout} onChange={e => setTimeoutValue(e.target.value)} placeholder={String(lim.serviceTimeout)} /></Field>
        </div>
        <fieldset className="cert-fs">
          <legend><b>Content check</b> <span className="muted sm">(optional)</span></legend>
          <div className="qa-assert" style={{ marginTop: 0 }}>
            <span className="sm">The page must</span>
            <select value={keywordMode} onChange={e => setKeywordMode(e.target.value as 'contains' | 'absent')}><option value="contains">contain</option><option value="absent">NOT contain</option></select>
            <input value={keyword} onChange={e => setKeyword(e.target.value)} placeholder={keywordMode === 'contains' ? 'Add to cart' : 'Error 500'} maxLength={200} />
          </div>
          <small className="muted">Case-insensitive, on the first 1 MB of the page. Catches pages that answer 200 but show an error or a blank template.</small>
        </fieldset>
        <fieldset className="cert-fs" disabled={!url.toLowerCase().startsWith('https://')}>
          <legend><label className="check"><input type="checkbox" checked={certCheck && url.toLowerCase().startsWith('https://')} onChange={e => setCertCheck(e.target.checked)} /><b>Watch the TLS certificate&apos;s expiry date</b></label></legend>
          {!url.toLowerCase().startsWith('https://') ? <p className="muted sm" style={{ margin: 0 }}>Only https:// addresses have a certificate.</p> : (
            <Field label="Alert this many days before it expires" hint={`Comma-separated, e.g. 30, 14, 7. Empty = ${lim.certDays.join(', ')} (default). One alert per step, plus one if it expires.`}>
              <input value={certDaysText} onChange={e => setCertDaysText(e.target.value)} placeholder={lim.certDays.join(', ')} disabled={!certCheck} inputMode="numeric" />
            </Field>)}
        </fieldset>
        <MonitorAlertSettings kind="service" value={alerts} onChange={setAlerts} />
        <label className="check"><input type="checkbox" checked={isPublic} onChange={e => setPublic(e.target.checked)} />Show on the public status page <span className="muted">(name and uptime only; the URL stays private)</span></label>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>
      </form>
    </Modal>
  );
}
