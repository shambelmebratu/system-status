'use client';

import { useEffect, useState } from 'react';
import { api, post, put } from '../lib/api';
import { useApp, useLimits, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

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
  transient: 'Logs that were fetched on demand. Deleted automatically after a short time.',
};
const size = (n: number | null) => (n == null ? '' : n > 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} KB`);

/** Admin: how long each kind of data is kept, the automatic purge schedule, and a manual purge. */
export function RetentionCard() {
  const lim = useLimits();
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

  if (!value) return <section className="card"><div className="card-head"><h2>Data retention</h2></div><p className="muted sm">Loading…</p></section>;
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
    if (!chosen.length) return;
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
  const totalRows = ORDER.reduce((n, k) => n + stats[k].rows, 0);
  const totalBytes = ORDER.reduce((n, k) => n + (stats[k].bytes ?? 0), 0);
  const when = !auto ? 'Automatic cleanup is off: nothing is deleted until you turn it on or delete by hand.'
    : frequency === 'hourly' ? 'Every hour, anything older than its limit is deleted.'
    : frequency === 'daily' ? `Every day at ${time} UTC, anything older than its limit is deleted.`
    : `Every ${WEEKDAYS[weekday]} at ${time} UTC, anything older than its limit is deleted.`;
  const chosen = ORDER.filter(k => picked[k]);
  return (
    <>
      <section className="card">
        <div className="card-head"><h2>Data retention</h2><span className="grow" /><span className="sm muted">{totalRows.toLocaleString()} rows stored{totalBytes ? ` · ${size(totalBytes)}` : ''}</span></div>
        <p className="muted sm" style={{ marginBottom: 6 }}>How long SM-Watch keeps its own history. Logs from your servers and clusters are not part of this: they are read on demand and dropped after {lim.logTtl} minutes.</p>

        <div className="ret-list">
          {ORDER.filter(k => k !== 'transient').map(k => (
            <div key={k} className="ret-row">
              <div className="ret-name"><b>{stats[k].label}</b><small>{HINT[k]}</small></div>
              <div className="ret-stored"><b>{stats[k].rows.toLocaleString()}</b> {stats[k].rows === 1 ? 'row' : 'rows'}{stats[k].bytes != null ? ` · ${size(stats[k].bytes)}` : ''}<small>{stats[k].oldest ? `oldest ${timeAgo(stats[k].oldest)}` : 'nothing stored'}</small></div>
              <label className="ret-keep"><span>Keep for</span><input type="number" min={k === 'audit' ? value.audit_min_days : 1} max={3650} value={days[k] ?? ''} onChange={e => setDays({ ...days, [k]: e.target.value })} aria-label={`Days to keep ${stats[k].label}`} /><span>days</span></label>
            </div>))}
        </div>

        <div className="ret-auto">
          <label className="switch"><input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)} /><span>Delete old data automatically</span></label>
          {auto && <div className="ret-when">
            <select value={frequency} onChange={e => setFrequency(e.target.value as Settings['frequency'])} aria-label="How often"><option value="hourly">Every hour</option><option value="daily">Once a day</option><option value="weekly">Once a week</option></select>
            {frequency === 'weekly' && <select value={weekday} onChange={e => setWeekday(Number(e.target.value))} aria-label="Day of the week">{WEEKDAYS.map((d, i) => <option key={d} value={i}>on {d}</option>)}</select>}
            {frequency !== 'hourly' && <label className="ret-time">at <input type="time" value={time} onChange={e => setTime(e.target.value)} aria-label="Time (UTC)" /> UTC</label>}
          </div>}
        </div>
        <p className="sm" style={{ margin: '10px 0 14px' }}>{when}</p>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <button className="btn primary" onClick={() => void save()} disabled={busy}>Save settings</button>
          <span className="sm muted">{settings.last_run_at ? `Last automatic cleanup ${timeAgo(settings.last_run_at)}.` : 'No automatic cleanup has run yet.'}</span>
        </div>
      </section>

      <section className="card danger-zone" style={{ marginTop: 16 }}>
        <div className="card-head"><h2>Delete data now</h2></div>
        <p className="muted sm" style={{ marginBottom: 12 }}>A one-off cleanup. It does not change the settings above, and it cannot be undone.</p>
        <div className="sm" style={{ fontWeight: 600, marginBottom: 8 }}>1. What to delete</div>
        <div className="pick-grid">{ORDER.map(k => (
          <label key={k} className={`pick-item ${picked[k] ? 'on' : ''}`}><input type="checkbox" checked={!!picked[k]} onChange={e => setPicked({ ...picked, [k]: e.target.checked })} /><span><b>{stats[k].label}</b><small>{stats[k].rows.toLocaleString()} {stats[k].rows === 1 ? 'row' : 'rows'}{stats[k].bytes != null ? ` · ${size(stats[k].bytes)}` : ''}</small></span></label>))}</div>
        <div className="sm" style={{ fontWeight: 600, margin: '14px 0 8px' }}>2. How much</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <select value={olderThan} onChange={e => setOlderThan(e.target.value)} aria-label="How much to delete">
            <option value="1">Everything older than 1 day</option><option value="7">Everything older than 7 days</option><option value="30">Everything older than 30 days</option><option value="90">Everything older than 90 days</option><option value="365">Everything older than 1 year</option><option value="0">Everything, including today</option>
          </select>
          <button className="btn danger" onClick={() => void purge()} disabled={busy || !chosen.length}>{chosen.length ? `Delete from ${chosen.length} selected…` : 'Select something first'}</button>
        </div>
        <p className="sm muted" style={{ marginTop: 10 }}>Open incidents are never deleted. Audit log entries newer than {value.audit_min_days} days are always kept. Every deletion is recorded in the audit log.{last && ` Last deletion by ${last.by} (${timeAgo(last.at)}): ${Object.entries(last.deleted).filter(([, n]) => n).map(([k, n]) => `${stats[k]?.label ?? k} ${n.toLocaleString()}`).join(', ') || 'nothing to delete'}.`}</p>
      </section>
    </>
  );
}
