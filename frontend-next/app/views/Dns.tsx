'use client';

import { FormEvent, useState } from 'react';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { Empty, Field, Icon, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, useLimits, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

type Records = Record<string, string[]>;
type DnsMon = MonitorAlerts & { id: number; name: string; domain: string; record_types: string[]; interval_seconds: number; enabled: boolean; check_expiry: boolean;
  expiry_alert_days: number[]; expiry_alert_days_effective: number[]; domain_expires_at: string | null; registrar: string | null; expiry_error: string | null;
  baseline: Records | null; current: Records | null; changes: string[]; changed_at: string | null; last_status: string; last_checked_at: string | null; last_error: string | null };

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA'];
const daysLeft = (iso: string | null) => (iso ? Math.floor((new Date(iso).getTime() - Date.now()) / 86400000) : null);
const tone = (d: number | null, steps: number[]) => (d == null ? 'none' : d < 0 || d <= Math.min(...steps) ? 'bad' : d <= Math.max(...steps) ? 'warn' : 'good');

export function Dns() {
  const { canManage, confirm, toast } = useApp();
  const list = usePoll(() => api<DnsMon[]>('/dns'), [], 30000);
  const [editing, setEditing] = useState<DnsMon | 'new' | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const items = list.value ?? [];
  async function act(m: DnsMon, what: 'check' | 'accept') {
    setBusy(m.id);
    try { await post(`/dns/${m.id}/${what}`); toast(what === 'accept' ? 'New records accepted' : 'Checked'); await list.reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(null); }
  }
  async function remove(m: DnsMon) { if (await confirm(`Stop watching ${m.domain}?`)) { await del(`/dns/${m.id}`); void list.reload(); } }
  return (
    <>
      <div className="topbar"><div><h1>DNS & domains</h1><p className="muted sm">Get alerted when DNS records change unexpectedly and before a domain registration expires.</p></div><span className="grow" />
        {canManage && <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />Watch a domain</button>}</div>
      {list.error && <div className="err">{list.error}</div>}
      {list.value && items.length === 0 && <div className="card"><Empty title="No domains watched" action={canManage ? <button className="btn primary" onClick={() => setEditing('new')}>Watch a domain</button> : undefined}>
        The first check remembers the current records as the accepted set. Later changes (a hijacked nameserver, a wrong A record, a missing MX) raise an alert until you accept them.</Empty></div>}
      <div className="dns-list">
        {items.map(m => { const d = daysLeft(m.domain_expires_at); const isOpen = open === m.id; return (
          <section key={m.id} className={`card dns-card ${m.last_status}`}>
            <div className="dns-head" onClick={() => setOpen(isOpen ? null : m.id)} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && setOpen(isOpen ? null : m.id)}>
              <span className="db-ico"><Icon name="globe" size={18} /></span>
              <div style={{ minWidth: 0 }}><div className="name">{m.name}</div><div className="mono sm muted">{m.domain}</div></div>
              <span className="grow" />
              {m.check_expiry && <span className={`cert-badge ${tone(d, m.expiry_alert_days_effective)}`} title={m.expiry_error ?? (m.domain_expires_at ? `Registered until ${new Date(m.domain_expires_at).toLocaleDateString()}` : '')}>{d == null ? (m.expiry_error ? 'no expiry data' : '…') : d < 0 ? 'expired' : `${d}d`}</span>}
              <StatusPill status={m.last_status} label={m.last_status === 'alert' ? 'Records changed' : m.last_status === 'up' ? 'As expected' : m.last_status === 'down' ? 'Not resolving' : 'Pending'} />
              <span className="muted">{isOpen ? '▾' : '▸'}</span>
            </div>
            {m.last_status === 'alert' && <div className="dns-change"><b>Changed {m.changed_at ? timeAgo(m.changed_at) : ''}:</b><ul>{m.changes.map((c, i) => <li key={i} className={c.includes(' added') ? 'add' : 'del'}>{c}</li>)}</ul>
              {canManage && <button className="btn sm primary" onClick={() => act(m, 'accept')} disabled={busy === m.id}>Accept as expected</button>}</div>}
            {m.last_status === 'down' && m.last_error && <div className="err" style={{ margin: '10px 0 0' }}>{m.last_error}</div>}
            {isOpen && <div className="dns-body">
              <table className="tbl"><thead><tr><th>Type</th><th>Records now</th><th className="hide-sm">Accepted</th></tr></thead><tbody>
                {m.record_types.map(t => { const now = m.current?.[t] ?? [], base = m.baseline?.[t] ?? []; const same = JSON.stringify(now) === JSON.stringify(base); return (
                  <tr key={t}><td><b>{t}</b></td><td className="mono sm">{now.length ? now.map(v => <div key={v} className={base.includes(v) ? '' : 'dns-new'}>{v}</div>) : <span className="muted">none</span>}</td>
                    <td className="mono sm hide-sm">{same ? <span className="muted">same</span> : base.length ? base.map(v => <div key={v} className={now.includes(v) ? '' : 'dns-gone'}>{v}</div>) : <span className="muted">none</span>}</td></tr>); })}
              </tbody></table>
              <div className="facts" style={{ marginTop: 12 }}>
                <div><small>Registration expires</small><b>{m.domain_expires_at ? new Date(m.domain_expires_at).toLocaleDateString(undefined, { dateStyle: 'medium' }) : m.check_expiry ? (m.expiry_error ?? 'checking…') : 'not watched'}</b></div>
                <div><small>Registrar</small><b>{m.registrar ?? '–'}</b></div>
                <div><small>Checked</small><b>{m.last_checked_at ? timeAgo(m.last_checked_at) : 'never'} · every {Math.round(m.interval_seconds / 60)} min</b></div>
                <div><small>Expiry alerts</small><b>{m.check_expiry ? `${m.expiry_alert_days_effective.join(', ')} days before` : 'off'}</b></div>
              </div>
              {canManage && <div style={{ display: 'flex', gap: 8, marginTop: 12 }}><button className="btn sm" onClick={() => act(m, 'check')} disabled={busy === m.id}><Icon name="refresh" size={14} />{busy === m.id ? 'Checking…' : 'Check now'}</button>
                <button className="btn sm" onClick={() => setEditing(m)}>Edit</button><button className="btn sm danger" onClick={() => remove(m)}>Stop watching</button></div>}
            </div>}
          </section>); })}
      </div>
      {editing && <DnsForm existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void list.reload(); }} />}
    </>
  );
}

function DnsForm({ existing, onClose, onSaved }: { existing?: DnsMon; onClose: () => void; onSaved: () => void }) {
  const lim = useLimits();
  const [name, setName] = useState(existing?.name ?? '');
  const [domain, setDomain] = useState(existing?.domain ?? '');
  const [types, setTypes] = useState<string[]>(existing?.record_types ?? ['A', 'AAAA', 'MX', 'NS', 'TXT']);
  const [interval, setIntervalValue] = useState(existing?.interval_seconds ?? 3600);
  const [expiry, setExpiry] = useState(existing?.check_expiry ?? true);
  const [days, setDays] = useState((existing?.expiry_alert_days ?? []).join(', '));
  const [alerts, setAlerts] = useState<MonitorAlerts>(alertsOf(existing));
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    const body = { name: name || domain, domain, record_types: types, interval_seconds: interval, check_expiry: expiry, expiry_alert_days: days.split(/[\s,]+/).filter(Boolean).map(Number), enabled: true, ...alerts };
    try { if (existing) await put(`/dns/${existing.id}`, body); else await post('/dns', body); onSaved(); } catch (e2) { setError((e2 as Error).message); } finally { setBusy(false); }
  }
  return (
    <Modal title={existing ? `Edit ${existing.domain}` : 'Watch a domain'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="form-grid">
          <Field label="Domain" hint="Just the name: example.com or api.example.com"><input className="mono" value={domain} onChange={e => setDomain(e.target.value.trim())} placeholder="example.com" required autoFocus={!existing} /></Field>
          <Field label="Name (optional)"><input value={name} onChange={e => setName(e.target.value)} placeholder="Company website" maxLength={100} /></Field>
          <Field label="Check every"><select value={interval} onChange={e => setIntervalValue(Number(e.target.value))}>{[300, 900, 1800, 3600, 21600, 86400].map(s => <option key={s} value={s}>{s >= 3600 ? `${s / 3600} h` : `${s / 60} min`}</option>)}</select></Field>
        </div>
        <div className="field">Records to watch<div className="chips" style={{ marginTop: 6 }}>{TYPES.map(t => <label key={t} className={`pick-item ${types.includes(t) ? 'on' : ''}`} style={{ padding: '6px 10px' }}><input type="checkbox" checked={types.includes(t)} onChange={e => setTypes(e.target.checked ? [...types, t] : types.filter(x => x !== t))} /><b>{t}</b></label>)}</div>
          <small>Changing the domain or the record types re-learns the accepted records.</small></div>
        <fieldset className="cert-fs"><legend><label className="check"><input type="checkbox" checked={expiry} onChange={e => setExpiry(e.target.checked)} /><b>Watch the registration&apos;s expiry date</b></label></legend>
          <Field label="Alert this many days before it expires" hint={`Empty = ${lim.certDays.join(', ')}. Read from RDAP; a few country domains do not publish it.`}><input value={days} onChange={e => setDays(e.target.value)} placeholder={lim.certDays.join(', ')} disabled={!expiry} /></Field>
        </fieldset>
        <MonitorAlertSettings kind="domain" value={alerts} onChange={setAlerts} />
        {error && <div className="err">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !types.length}>{busy ? 'Checking…' : existing ? 'Save' : 'Start watching'}</button></div>
      </form>
    </Modal>
  );
}
