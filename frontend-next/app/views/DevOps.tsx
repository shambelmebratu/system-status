'use client';

import { FormEvent, useMemo, useState } from 'react';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { CodeBox, Empty, Field, Icon, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { ms, timeAgo, uptimeClass } from '../lib/format';

type Monitor = { key: string; kind: string; id: number; name: string; status: string };
const KIND_LABEL: Record<string, string> = { server: 'Server', service: 'Service', cluster: 'Cluster', test: 'API test', dns: 'Domain', heartbeat: 'Cron job' };
const human = (s: number) => (s < 120 ? `${s} s` : s < 7200 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`);

/* ================================================================ Cron jobs (heartbeats) */
type Hb = MonitorAlerts & { id: number; name: string; description: string; period_seconds: number; grace_seconds: number; enabled: boolean; ping_url: string; last_ping_at: string | null;
  next_due_at: string | null; overdue: boolean; running_since: string | null; last_duration_ms: number | null; last_status: string; last_error: string | null };
type Ping = { ts: string; kind: 'success' | 'start' | 'fail'; duration_ms: number | null; message: string | null; ip: string | null };
const PERIODS: [number, string][] = [[300, 'every 5 minutes'], [900, 'every 15 minutes'], [3600, 'every hour'], [21600, 'every 6 hours'], [43200, 'every 12 hours'], [86400, 'every day'], [604800, 'every week']];

export function Heartbeats() {
  const { canManage, confirm, toast } = useApp();
  const list = usePoll(() => api<Hb[]>('/heartbeats'), [], 15000);
  const [editing, setEditing] = useState<Hb | 'new' | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const items = list.value ?? [];
  async function newUrl(h: Hb) {
    if (!(await confirm(`Replace the ping URL of "${h.name}"?\n\nThe old URL stops working at once: update the job to use the new one.`))) return;
    await post(`/heartbeats/${h.id}/new-url`); toast('New ping URL created'); void list.reload();
  }
  async function remove(h: Hb) { if (await confirm(`Delete "${h.name}"?`)) { await del(`/heartbeats/${h.id}`); void list.reload(); } }
  return (
    <>
      <div className="topbar"><div><h1>Cron jobs</h1><p className="muted sm">Backups, imports and scheduled jobs report in by calling a URL. If a job fails or does not report on time, you get an alert.</p></div><span className="grow" />
        {canManage && <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />Watch a job</button>}</div>
      {list.value && items.length === 0 && <div className="card"><Empty title="No jobs watched yet" action={canManage ? <button className="btn primary" onClick={() => setEditing('new')}>Watch a job</button> : undefined}>
        Each job gets its own secret URL. Add one line to the end of the job, e.g. <code>curl -fsS https://…/api/ping/hb_…</code>.</Empty></div>}
      <div className="dns-list">
        {items.map(h => { const isOpen = open === h.id; return (
          <section key={h.id} className={`card dns-card ${h.last_status}`}>
            <div className="dns-head" onClick={() => setOpen(isOpen ? null : h.id)} role="button" tabIndex={0}>
              <span className="db-ico"><Icon name="clock" size={18} /></span>
              <div style={{ minWidth: 0 }}><div className="name">{h.name}{!h.enabled && <> <span className="tag">paused</span></>}</div><div className="sm muted">expected {PERIODS.find(p => p[0] === h.period_seconds)?.[1] ?? `every ${human(h.period_seconds)}`} · {human(h.grace_seconds)} grace</div></div>
              <span className="grow" />
              {h.running_since && <span className="tag">running since {timeAgo(h.running_since)}</span>}
              <span className="sm muted hide-sm">{h.last_ping_at ? `last ping ${timeAgo(h.last_ping_at)}` : 'no ping yet'}{h.last_duration_ms ? ` · took ${ms(h.last_duration_ms)}` : ''}</span>
              <StatusPill status={h.last_status} label={h.last_status === 'up' ? 'On time' : h.last_status === 'down' ? (h.overdue ? 'Late' : 'Failed') : 'Waiting'} />
              <span className="muted">{isOpen ? '▾' : '▸'}</span>
            </div>
            {h.last_status === 'down' && h.last_error && <div className="err" style={{ margin: '10px 0 0' }}>{h.last_error}</div>}
            {isOpen && <HeartbeatDetail h={h} onEdit={() => setEditing(h)} onNewUrl={() => newUrl(h)} onDelete={() => remove(h)} />}
          </section>); })}
      </div>
      {editing && <HeartbeatForm existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={h => { setEditing(null); setOpen(h.id); void list.reload(); }} />}
    </>
  );
}

function HeartbeatDetail({ h, onEdit, onNewUrl, onDelete }: { h: Hb; onEdit: () => void; onNewUrl: () => void; onDelete: () => void }) {
  const { canManage } = useApp();
  const pings = usePoll(() => api<Ping[]>(`/heartbeats/${h.id}/pings?limit=60`), [h.id, h.last_ping_at], 30000);
  const [tab, setTab] = useState<'cron' | 'script' | 'k8s'>('cron');
  const examples = {
    cron: `# crontab: report success when the job worked, failure (with its output) when it did not\n0 2 * * * /usr/local/bin/backup.sh > /tmp/backup.log 2>&1 && curl -fsS -m 10 --retry 3 ${h.ping_url} || curl -fsS -m 10 --retry 3 --data-binary @/tmp/backup.log ${h.ping_url}/fail`,
    script: `#!/usr/bin/env bash\n# measures how long the job takes and sends the last lines of output if it fails\ncurl -fsS -m 10 ${h.ping_url}/start\nif output=$(/usr/local/bin/backup.sh 2>&1); then\n  curl -fsS -m 10 --retry 3 ${h.ping_url}\nelse\n  echo "$output" | tail -n 50 | curl -fsS -m 10 --retry 3 --data-binary @- ${h.ping_url}/fail\nfi`,
    k8s: `# Kubernetes CronJob: add to the container's command\ncommand: ["/bin/sh", "-c", "run-job && wget -qO- ${h.ping_url} || wget -qO- ${h.ping_url}/fail"]`,
  };
  return (
    <div className="dns-body">
      <div className="field">Ping URL <small>keep it private: anyone with it can report for this job</small><CodeBox value={h.ping_url} /></div>
      <div className="seg" style={{ margin: '10px 0 6px' }}>{(['cron', 'script', 'k8s'] as const).map(t => <button key={t} className={tab === t ? 'on' : ''} onClick={() => setTab(t)}>{t === 'cron' ? 'crontab' : t === 'script' ? 'Bash script' : 'Kubernetes'}</button>)}</div>
      <CodeBox value={examples[tab]} />
      <p className="muted sm">Signals: <code>/api/ping/…</code> success · <code>…/start</code> started (to measure duration) · <code>…/fail</code> failed (POST text to include the job&apos;s output).</p>
      <h3 className="drawer-h">Recent pings</h3>
      {!pings.value?.length ? <p className="muted sm">None yet.</p> : <div className="qa-bars" style={{ height: 40 }}>{[...pings.value].reverse().filter(p => p.kind !== 'start').map((p, i) => <span key={i} className={`qa-bar ${p.kind === 'fail' ? 'failed' : 'passed'}`} title={`${new Date(p.ts).toLocaleString()} · ${p.kind}${p.duration_ms ? ` · ${ms(p.duration_ms)}` : ''}${p.message ? `\n${p.message.slice(0, 200)}` : ''}`} style={{ height: '100%' }} />)}</div>}
      <table className="tbl" style={{ marginTop: 8 }}><tbody>{(pings.value ?? []).slice(0, 10).map((p, i) => <tr key={i}><td className="sm">{new Date(p.ts).toLocaleString()}</td><td><span className={`qa-result ${p.kind === 'fail' ? 'failed' : p.kind === 'success' ? 'passed' : ''}`}>{p.kind}</span></td>
        <td className="sm">{p.duration_ms ? ms(p.duration_ms) : ''}</td><td className="sm mono muted trunc" style={{ maxWidth: 360 }} title={p.message ?? ''}>{p.message ?? ''}</td><td className="sm muted hide-sm">{p.ip}</td></tr>)}</tbody></table>
      {canManage && <div style={{ display: 'flex', gap: 8, marginTop: 12 }}><button className="btn sm" onClick={onEdit}>Edit</button><button className="btn sm" onClick={onNewUrl}>New ping URL</button><button className="btn sm danger" onClick={onDelete}>Delete</button></div>}
    </div>
  );
}

function HeartbeatForm({ existing, onClose, onSaved }: { existing?: Hb; onClose: () => void; onSaved: (h: Hb) => void }) {
  const [name, setName] = useState(existing?.name ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [period, setPeriod] = useState(existing?.period_seconds ?? 86400);
  const [grace, setGrace] = useState(existing?.grace_seconds ?? 3600);
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [alerts, setAlerts] = useState<MonitorAlerts>(alertsOf(existing));
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    const body = { name, description, period_seconds: period, grace_seconds: grace, enabled, ...alerts };
    try { onSaved(existing ? await put<Hb>(`/heartbeats/${existing.id}`, body) : await post<Hb>('/heartbeats', body)); } catch (e2) { setError((e2 as Error).message); } finally { setBusy(false); }
  }
  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'Watch a job'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="form-grid">
          <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder="Nightly database backup" required autoFocus maxLength={100} /></Field>
          <Field label="Description (optional)"><input value={description} onChange={e => setDescription(e.target.value)} placeholder="pg_dump to S3 on db-01" maxLength={500} /></Field>
          <Field label="The job runs" hint="How often a ping is expected"><select value={period} onChange={e => setPeriod(Number(e.target.value))}>{PERIODS.map(([s, l]) => <option key={s} value={s}>{l}</option>)}{!PERIODS.some(p => p[0] === period) && <option value={period}>every {human(period)}</option>}</select></Field>
          <Field label="Grace time" hint="How late a ping may be (jobs take time)"><select value={grace} onChange={e => setGrace(Number(e.target.value))}>{[60, 300, 900, 1800, 3600, 7200, 21600].map(s => <option key={s} value={s}>{human(s)}</option>)}</select></Field>
        </div>
        <label className="check"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Watching (untick to pause, e.g. while the job is switched off)</label>
        <MonitorAlertSettings kind="job" value={alerts} onChange={setAlerts} />
        {error && <div className="err">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : existing ? 'Save' : 'Create and show the ping URL'}</button></div>
      </form>
    </Modal>
  );
}

/* ================================================================ Maintenance windows */
type Window = { id: number; title: string; description: string; starts_at: string; ends_at: string; targets: string[]; suppress_alerts: boolean; show_on_status: boolean; state: 'active' | 'upcoming' | 'done'; created_by: string | null };
const local = (iso: string) => { const d = new Date(iso); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
const fmt = (iso: string) => new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

function MonitorPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const monitors = usePoll(() => api<Monitor[]>('/monitors'), [], 0);
  const [q, setQ] = useState('');
  const list = (monitors.value ?? []).filter(m => !q || `${m.name} ${KIND_LABEL[m.kind]}`.toLowerCase().includes(q.toLowerCase()));
  return <div className="acc" style={{ marginTop: 6 }}>
    <label className="lg-field"><Icon name="logs" size={15} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Find a monitor…" /></label>
    <div className="acc-list" style={{ maxHeight: 220, border: '1px solid var(--line)', borderRadius: 10 }}>{list.map(m => <label key={m.key} className={`acc-item ${value.includes(m.key) ? 'on' : ''}`}><input type="checkbox" checked={value.includes(m.key)} onChange={e => onChange(e.target.checked ? [...value, m.key] : value.filter(k => k !== m.key))} /><span>{m.name}</span><small>{KIND_LABEL[m.kind]}</small></label>)}</div>
  </div>;
}

export function MaintenanceView() {
  const { canManage, confirm } = useApp();
  const list = usePoll(() => api<Window[]>('/maintenance'), [], 30000);
  const monitors = usePoll(() => api<Monitor[]>('/monitors').catch(() => [] as Monitor[]), [], 0);
  const names = useMemo(() => new Map((monitors.value ?? []).map(m => [m.key, m.name])), [monitors.value]);
  const [editing, setEditing] = useState<Window | 'new' | null>(null);
  const items = list.value ?? [];
  const groups: [string, Window[]][] = [['Now', items.filter(w => w.state === 'active')], ['Planned', items.filter(w => w.state === 'upcoming')], ['Finished (last 30 days)', items.filter(w => w.state === 'done').reverse()]];
  return (
    <>
      <div className="topbar"><div><h1>Maintenance</h1><p className="muted sm">Plan downtime: alerts are held back for the chosen monitors and the public status page announces it.</p></div><span className="grow" />
        {canManage && <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />Plan maintenance</button>}</div>
      {list.value && items.length === 0 && <div className="card"><Empty title="No maintenance planned" action={canManage ? <button className="btn primary" onClick={() => setEditing('new')}>Plan maintenance</button> : undefined}>During a window, monitors still record what happens (so history stays honest), but nobody is woken up for planned work.</Empty></div>}
      {groups.map(([label, ws]) => ws.length > 0 && <section key={label} className="card" style={{ marginBottom: 12 }}><div className="card-head"><h2>{label}</h2></div>
        {ws.map(w => <div key={w.id} className={`mw-row ${w.state}`}>
          <div style={{ minWidth: 0 }}><b>{w.title}</b>{w.state === 'active' && <span className="tag good" style={{ marginLeft: 8 }}>in progress</span>}
            <div className="sm muted">{fmt(w.starts_at)} → {fmt(w.ends_at)} · {w.targets.length ? w.targets.map(k => names.get(k) ?? k).join(', ') : 'all monitors'}</div>
            <div className="sm muted">{w.suppress_alerts ? 'alerts held back' : 'alerts still sent'} · {w.show_on_status ? 'shown on the status page' : 'internal only'}{w.description ? ` · ${w.description}` : ''}</div></div>
          <span className="grow" />
          {canManage && w.state !== 'done' && <><button className="btn sm" onClick={() => setEditing(w)}>Edit</button>{w.state === 'active' && <button className="btn sm" onClick={async () => { await post(`/maintenance/${w.id}/end`); void list.reload(); }}>End now</button>}</>}
          {canManage && <button className="btn sm danger" onClick={async () => { if (await confirm(`Delete "${w.title}"?`)) { await del(`/maintenance/${w.id}`); void list.reload(); } }}>Delete</button>}
        </div>)}</section>)}
      {editing && <MaintenanceForm existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void list.reload(); }} />}
    </>
  );
}

function MaintenanceForm({ existing, onClose, onSaved }: { existing?: Window; onClose: () => void; onSaved: () => void }) {
  const start = new Date(Date.now() + 3600000); start.setMinutes(0, 0, 0);
  const [title, setTitle] = useState(existing?.title ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [from, setFrom] = useState(existing ? local(existing.starts_at) : local(start.toISOString()));
  const [to, setTo] = useState(existing ? local(existing.ends_at) : local(new Date(start.getTime() + 2 * 3600000).toISOString()));
  const [all, setAll] = useState(!existing?.targets.length);
  const [targets, setTargets] = useState<string[]>(existing?.targets ?? []);
  const [suppress, setSuppress] = useState(existing?.suppress_alerts ?? true);
  const [show, setShow] = useState(existing?.show_on_status ?? true);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    const body = { title, description, starts_at: new Date(from).toISOString(), ends_at: new Date(to).toISOString(), targets: all ? [] : targets, suppress_alerts: suppress, show_on_status: show };
    try { if (existing) await put(`/maintenance/${existing.id}`, body); else await post('/maintenance', body); onSaved(); } catch (e2) { setError((e2 as Error).message); } finally { setBusy(false); }
  }
  return (
    <Modal title={existing ? 'Edit maintenance' : 'Plan maintenance'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="form-grid">
          <Field label="Title" hint="Shown on the status page"><input value={title} onChange={e => setTitle(e.target.value)} placeholder="Database upgrade" required maxLength={150} autoFocus /></Field>
          <Field label="Details (optional)"><input value={description} onChange={e => setDescription(e.target.value)} placeholder="Checkout may be unavailable for a few minutes" maxLength={2000} /></Field>
          <Field label="Starts (your local time)"><input type="datetime-local" value={from} onChange={e => setFrom(e.target.value)} required /></Field>
          <Field label="Ends"><input type="datetime-local" value={to} onChange={e => setTo(e.target.value)} required /></Field>
        </div>
        <div className="field">Affected monitors
          <div className="method" style={{ marginTop: 6 }}><button type="button" className={all ? 'on' : ''} onClick={() => setAll(true)}><b>Everything</b><span>All servers, services, clusters, tests, domains and jobs.</span></button><button type="button" className={!all ? 'on' : ''} onClick={() => setAll(false)}><b>Only selected</b><span>Just the monitors ticked below.</span></button></div>
          {!all && <MonitorPicker value={targets} onChange={setTargets} />}</div>
        <label className="check"><input type="checkbox" checked={suppress} onChange={e => setSuppress(e.target.checked)} />Hold back alerts during the window <span className="muted sm">(incidents and history are still recorded)</span></label>
        <label className="check"><input type="checkbox" checked={show} onChange={e => setShow(e.target.checked)} />Announce it on the public status page <span className="muted sm">(when it affects a public monitor, or everything)</span></label>
        {error && <div className="err">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || (!all && !targets.length)}>{busy ? 'Saving…' : 'Save'}</button></div>
      </form>
    </Modal>
  );
}

/* ================================================================ SLOs */
type SloRow = { id: number; name: string; target: string; target_type: string; target_name: string; objective: number; window_days: number; burn_alerts: boolean; sli: number | null; checks: number; failed: number;
  budget_remaining_pct: number | null; allowed_downtime_minutes: number; used_downtime_minutes: number; state: 'ok' | 'slow' | 'fast' | 'exhausted'; burn_1h: number | null; burn_6h: number | null;
  budget_gone_in_hours?: number | null; daily: { date: string; pct: number | null }[] };
const STATE: Record<SloRow['state'], [string, string]> = { ok: ['Healthy', 'good'], slow: ['Burning', 'warn'], fast: ['Burning fast', 'bad'], exhausted: ['Budget exhausted', 'bad'] };
const minutes = (m: number) => (m < 120 ? `${Math.round(m)} min` : `${(m / 60).toFixed(1)} h`);

export function Slos() {
  const { canManage, confirm } = useApp();
  const list = usePoll(() => api<SloRow[]>('/slos'), [], 60000);
  const [editing, setEditing] = useState<SloRow | 'new' | null>(null);
  const items = list.value ?? [];
  return (
    <>
      <div className="topbar"><div><h1>SLOs & error budgets</h1><p className="muted sm">An objective like “99.9 % available over 30 days” allows 43 minutes of downtime. See how much of that budget is left, and get warned when it burns too fast.</p></div><span className="grow" />
        {canManage && <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />New SLO</button>}</div>
      {list.value && items.length === 0 && <div className="card"><Empty title="No SLOs yet" action={canManage ? <button className="btn primary" onClick={() => setEditing('new')}>Create an SLO</button> : undefined}>Any monitor can have one: a service, server, API test, domain or cron job.</Empty></div>}
      <div className="slo-grid">
        {items.map(s => { const [label, tone] = STATE[s.state]; const left = s.budget_remaining_pct; return (
          <section key={s.id} className={`card slo-card ${tone}`}>
            <div className="card-head" style={{ marginBottom: 6 }}><div style={{ minWidth: 0 }}><h2 style={{ textTransform: 'none', letterSpacing: 0, fontSize: 16 }} className="trunc">{s.name}</h2><div className="sm muted">{KIND_LABEL[s.target_type]} · {s.target_name} · {s.objective}% over {s.window_days} days</div></div>
              <span className="grow" /><span className={`kstatus ${tone === 'good' ? 'ok' : tone}`}><i />{label}</span></div>
            <div className="slo-main">
              <div><small>Availability</small><b className={uptimeClass(s.sli)}>{s.sli == null ? '–' : `${s.sli.toFixed(s.objective >= 99.9 ? 3 : 2)}%`}</b></div>
              <div><small>Error budget left</small><b className={left == null ? '' : left <= 0 ? 'bad' : left < 25 ? 'warn' : 'good'}>{left == null ? '–' : `${Math.max(left, -999).toFixed(0)}%`}</b></div>
              <div><small>Downtime used</small><b className="sm-b">{minutes(s.used_downtime_minutes)} <span className="muted">/ {minutes(s.allowed_downtime_minutes)}</span></b></div>
            </div>
            <div className="slo-bar"><i className={left == null ? '' : left <= 0 ? 'bad' : left < 25 ? 'warn' : 'good'} style={{ width: `${Math.max(0, Math.min(100, left ?? 0))}%` }} /></div>
            <div className="slo-days" title="Daily availability (red: below the objective)">{s.daily.map(d => <span key={d.date} className={d.pct == null ? 'none' : d.pct >= s.objective ? 'good' : 'bad'} title={`${d.date}: ${d.pct ?? '–'}%`} />)}</div>
            <div className="sm muted" style={{ marginTop: 8 }}>Burn rate {s.burn_1h ?? '–'}× (1 h) · {s.burn_6h ?? '–'}× (6 h){s.budget_gone_in_hours ? ` · budget gone in ~${s.budget_gone_in_hours} h at this rate` : ''} · {s.checks.toLocaleString()} checks, {s.failed.toLocaleString()} failed</div>
            {canManage && <div style={{ display: 'flex', gap: 8, marginTop: 10 }}><button className="btn sm" onClick={() => setEditing(s)}>Edit</button><button className="btn sm danger" onClick={async () => { if (await confirm(`Delete the SLO "${s.name}"?`)) { await del(`/slos/${s.id}`); void list.reload(); } }}>Delete</button></div>}
          </section>); })}
      </div>
      {items.length > 0 && <p className="muted sm">Burn rate 1× uses the budget exactly over the window. Alerts: <b>fast</b> when the last hour and 5 minutes both burn above 14.4×, <b>slow</b> when the last 6 hours and 30 minutes both burn above 6×, and when the budget is gone.</p>}
      {editing && <SloForm existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void list.reload(); }} />}
    </>
  );
}

function SloForm({ existing, onClose, onSaved }: { existing?: SloRow; onClose: () => void; onSaved: () => void }) {
  const monitors = usePoll(() => api<Monitor[]>('/monitors'), [], 0);
  const [name, setName] = useState(existing?.name ?? '');
  const [target, setTarget] = useState(existing?.target ?? '');
  const [objective, setObjective] = useState(existing?.objective ?? 99.9);
  const [windowDays, setWindowDays] = useState(existing?.window_days ?? 30);
  const [burn, setBurn] = useState(existing?.burn_alerts ?? true);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const allowed = windowDays * 1440 * (1 - objective / 100);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    const monitor = monitors.value?.find(m => m.key === target);
    const body = { name: name || `${monitor?.name ?? 'Monitor'} availability`, target, objective, window_days: windowDays, burn_alerts: burn };
    try { if (existing) await put(`/slos/${existing.id}`, body); else await post('/slos', body); onSaved(); } catch (e2) { setError((e2 as Error).message); } finally { setBusy(false); }
  }
  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'New SLO'} onClose={onClose}>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <Field label="Monitor"><select value={target} onChange={e => setTarget(e.target.value)} required><option value="">Choose…</option>
          {Object.entries(KIND_LABEL).map(([k, l]) => { const ms2 = (monitors.value ?? []).filter(m => m.kind === k); return ms2.length ? <optgroup key={k} label={l + 's'}>{ms2.map(m => <option key={m.key} value={m.key}>{m.name}</option>)}</optgroup> : null; })}</select></Field>
        <Field label="Name (optional)"><input value={name} onChange={e => setName(e.target.value)} placeholder="Checkout availability" maxLength={100} /></Field>
        <div className="field">Objective<div className="seg" style={{ marginTop: 6 }}>{[99, 99.5, 99.9, 99.95, 99.99].map(o => <button type="button" key={o} className={objective === o ? 'on' : ''} onClick={() => setObjective(o)}>{o}%</button>)}</div></div>
        <div className="field">Window<div className="seg" style={{ marginTop: 6 }}>{[7, 28, 30, 90].map(d => <button type="button" key={d} className={windowDays === d ? 'on' : ''} onClick={() => setWindowDays(d)}>{d} days</button>)}</div>
          <small>Allows {minutes(allowed)} of downtime per {windowDays} days.</small></div>
        <label className="check"><input type="checkbox" checked={burn} onChange={e => setBurn(e.target.checked)} />Alert when the error budget burns too fast or runs out</label>
        {error && <div className="err">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !target}>{busy ? 'Saving…' : 'Save'}</button></div>
      </form>
    </Modal>
  );
}
