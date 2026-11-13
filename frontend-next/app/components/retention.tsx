'use client';

import { useEffect, useState } from 'react';
import { api, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';
import { Field } from './ui';

type Stat = { label: string; rows: number; oldest: string | null; bytes: number | null };
type Settings = {
  days: Record<string, number>; auto: boolean; frequency: 'hourly' | 'daily' | 'weekly'; time: string; weekday: number;
  last_run_at: string | null; last_result: { by: string; at: string; deleted: Record<string, number> } | null;
};
type View = { settings: Settings; stats: Record<string, Stat>; audit_min_days: number };

const ORDER = ['checks', 'metrics', 'alerts', 'incidents', 'audit', 'links', 'transient'];
const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const HINT: Record<string, string> = {
  checks: 'One row per check; the biggest table over time.', metrics: 'CPU, memory, disk and network samples.', alerts: 'Sent alert messages and their delivery state.',
  incidents: 'Resolved incidents only. Open ones are never purged.', audit: 'Who did what. Kept at least 30 days.', links: 'Expired or revoked install links.',
  transient: 'Logs that were fetched on demand. Already deleted after 15 minutes.',
};
const size = (n: number | null) => (n == null ? '' : n > 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} KB`);

/** Admin: how long each kind of data is kept, the automatic purge schedule, and a manual purge. */
export function RetentionCard() {
  const { toast, confirm } = useApp();
  const { value, reload } = usePoll(() => api<View>('/retention'), [], 30000);
  const [days, setDays] = useState<Record<string, string>>({});
  const [auto, setAuto] = useState(true);
  const [frequency, setFrequency] = useState<Settings['frequency']>('hourly');
  const [time, setTime] = useState('03:00');
  const [weekday, setWeekday] = useState(0);
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [olderThan, setOlderThan] = useState('30');
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!value || loaded) return;   // fill the form once; later refreshes only update the numbers
    const s = value.settings;
    setDays(Object.fromEntries(Object.entries(s.days).map(([k, v]) => [k, String(v)])));
    setAuto(s.auto); setFrequency(s.frequency); setTime(s.time); setWeekday(s.weekday); setLoaded(true);
  }, [value, loaded]);

  if (!value) return <section className="card" style={{ marginTop: 16 }}><div className="card-head"><h2>Data retention & purge</h2></div><p className="muted sm">Loading…</p></section>;
  const { stats, settings } = value;

  async function save() {
    setBusy(true);
    try {
      await put('/retention', { days: Object.fromEntries(Object.entries(days).map(([k, v]) => [k, Number(v)])), auto, frequency, time, weekday });
      toast('Retention settings saved'); await reload();
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  async function purge() {
    const chosen = ORDER.filter(k => picked[k]);
    if (!chosen.length) { toast('Tick the kinds of data to purge first', true); return; }
    const scope = Number(olderThan) === 0 ? 'EVERYTHING' : `everything older than ${olderThan} days`;
    const rows = chosen.reduce((n, k) => n + stats[k].rows, 0);
    if (!(await confirm(`Permanently delete ${scope} in:\n\n${chosen.map(k => `• ${stats[k].label}`).join('\n')}\n\nUp to ${rows.toLocaleString()} rows. This cannot be undone.`))) return;
    setBusy(true);
    try {
      const r = await post<{ deleted: Record<string, number> }>('/retention/purge', { categories: chosen, older_than_days: Number(olderThan) });
      toast(`Purged ${Object.values(r.deleted).reduce((a, b) => a + b, 0).toLocaleString()} rows`); setPicked({}); await reload();
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }

  const last = settings.last_result;
  return (
    <section className="card" style={{ marginTop: 16 }}>
      <div className="card-head"><h2>Data retention & purge</h2></div>
      <p className="muted sm" style={{ marginBottom: 14 }}>Choose how long each kind of data is kept. Anything older is deleted automatically on the schedule below, or you can purge by hand. Logs from your servers and clusters are never stored here: they are read on demand and dropped after 15 minutes.</p>
      <div className="tbl-wrap"><table className="tbl">
        <thead><tr><th style={{ width: 28 }} /><th>Data</th><th className="num">Rows</th><th className="hide-sm">Oldest</th><th className="num hide-sm">Size</th><th style={{ width: 150 }}>Keep for</th></tr></thead>
        <tbody>{ORDER.map(k => (
          <tr key={k}>
            <td><input type="checkbox" checked={!!picked[k]} onChange={e => setPicked({ ...picked, [k]: e.target.checked })} aria-label={`Select ${stats[k].label} for purge`} /></td>
            <td><div className="name">{stats[k].label}<small>{HINT[k]}</small></div></td>
            <td className="num">{stats[k].rows.toLocaleString()}</td>
            <td className="hide-sm sm muted">{stats[k].oldest ? timeAgo(stats[k].oldest) : '–'}</td>
            <td className="num hide-sm sm muted">{size(stats[k].bytes)}</td>
            <td>{k === 'transient' ? <span className="muted sm">15 minutes</span> : <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}><input type="number" style={{ width: 80 }} min={k === 'audit' ? value.audit_min_days : 1} max={3650} value={days[k] ?? ''} onChange={e => setDays({ ...days, [k]: e.target.value })} aria-label={`Days to keep ${stats[k].label}`} /> days</span>}</td>
          </tr>))}
        </tbody></table></div>

      <div className="form-grid" style={{ marginTop: 16, alignItems: 'end' }}>
        <label className="check" style={{ alignSelf: 'center' }}><input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)} />Purge automatically</label>
        <Field label="How often"><select value={frequency} onChange={e => setFrequency(e.target.value as Settings['frequency'])} disabled={!auto}><option value="hourly">Every hour</option><option value="daily">Every day</option><option value="weekly">Every week</option></select></Field>
        {frequency === 'weekly' && <Field label="On"><select value={weekday} onChange={e => setWeekday(Number(e.target.value))} disabled={!auto}>{WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}</select></Field>}
        {frequency !== 'hourly' && <Field label="At (UTC)"><input type="time" value={time} onChange={e => setTime(e.target.value)} disabled={!auto} /></Field>}
        <button className="btn primary" onClick={() => void save()} disabled={busy}>Save retention</button>
      </div>
      <p className="sm muted" style={{ marginTop: 8 }}>{settings.last_run_at ? `Last automatic purge ${timeAgo(settings.last_run_at)}.` : 'No automatic purge has run yet.'}{last && ` Last purge by ${last.by} (${timeAgo(last.at)}): ${Object.entries(last.deleted).filter(([, n]) => n).map(([k, n]) => `${stats[k]?.label ?? k} ${n.toLocaleString()}`).join(', ') || 'nothing to delete'}.`}</p>

      <div className="card" style={{ background: 'var(--bg)', marginTop: 14 }}>
        <b className="sm">Purge now</b>
        <p className="sm muted" style={{ margin: '4px 0 10px' }}>Tick the data kinds in the table, then choose what to delete.</p>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <select value={olderThan} onChange={e => setOlderThan(e.target.value)} aria-label="Purge scope">
            <option value="1">Older than 1 day</option><option value="7">Older than 7 days</option><option value="30">Older than 30 days</option><option value="90">Older than 90 days</option><option value="365">Older than 1 year</option><option value="0">Everything</option>
          </select>
          <button className="btn danger" onClick={() => void purge()} disabled={busy}>Purge selected…</button>
          <span className="sm muted">The audit log can only be purged for entries older than {value.audit_min_days} days. Every purge is recorded in the audit log.</span>
        </div>
      </div>
    </section>
  );
}
