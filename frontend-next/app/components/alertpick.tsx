'use client';

import { useApp, useLimits } from '../lib/app';

export const EVENTS: { id: string; label: string; hint: string }[] = [
  { id: 'down', label: 'Down', hint: 'It stopped responding' },
  { id: 'alert', label: 'Over a limit', hint: 'A threshold or problem was detected' },
  { id: 'recovered', label: 'Recovered', hint: 'It is healthy again' },
  { id: 'reminder', label: 'Reminders', hint: 'Repeats while it is still failing' },
];

export type MonitorAlerts = { alert_events: string[]; alert_channels: number[]; alert_reminder_minutes: number | null };
export const alertsOf = (x?: { alert_events?: string[]; alert_channels?: number[]; alert_reminder_minutes?: number | null }): MonitorAlerts =>
  ({ alert_events: x?.alert_events ?? [], alert_channels: x?.alert_channels ?? [], alert_reminder_minutes: x?.alert_reminder_minutes ?? null });

const PRESETS: [string, number][] = [['5 min', 5], ['15 min', 15], ['30 min', 30], ['1 hour', 60], ['4 hours', 240], ['1 day', 1440], ['Never', 0]];

/** Which alerts this server / service / cluster sends, to which channels, and how often it repeats. Empty = inherit the defaults. */
export function MonitorAlertSettings({ kind, value, onChange, pingOnly }: { kind: string; value: MonitorAlerts; onChange: (v: MonitorAlerts) => void; pingOnly?: boolean }) {
  const { channels } = useApp();
  const lim = useLimits();
  const applicable = EVENTS.filter(e => !(e.id === 'alert' && pingOnly));
  const all = applicable.map(e => e.id);
  const events = value.alert_events.length ? value.alert_events.filter(e => all.includes(e)) : all;
  const toggleEvent = (id: string) => {
    const next = events.includes(id) ? events.filter(e => e !== id) : [...events, id];
    if (next.length) onChange({ ...value, alert_events: next.length === all.length ? [] : next });   // at least one type stays ticked
  };
  const specific = value.alert_channels.length > 0;
  const toggleChannel = (id: number) => onChange({ ...value, alert_channels: value.alert_channels.includes(id) ? value.alert_channels.filter(c => c !== id) : [...value.alert_channels, id] });
  const minutes = value.alert_reminder_minutes;
  const reminderOn = events.includes('reminder');
  return (
    <fieldset className="pick">
      <legend>Alerts for this {kind}</legend>
      <div>
        <div className="sm" style={{ fontWeight: 600, marginBottom: 6 }}>Send these alert types</div>
        <div className="pick-grid">{applicable.map(e => (
          <label key={e.id} className={`pick-item ${events.includes(e.id) ? 'on' : ''}`}><input type="checkbox" checked={events.includes(e.id)} onChange={() => toggleEvent(e.id)} /><span><b>{e.label}</b><small>{e.hint}</small></span></label>))}</div>
      </div>
      <div>
        <div className="sm" style={{ fontWeight: 600, marginBottom: 6 }}>Send them to</div>
        <div className="pick-row">
          <label className="check"><input type="radio" name={`ch-${kind}`} checked={!specific} onChange={() => onChange({ ...value, alert_channels: [] })} />All channels</label>
          <label className="check"><input type="radio" name={`ch-${kind}`} checked={specific} onChange={() => channels[0] && onChange({ ...value, alert_channels: [channels[0].id] })} disabled={channels.length === 0} />Only these channels</label>
        </div>
        {specific && <div className="pick-row" style={{ marginTop: 8, paddingLeft: 22 }}>{channels.map(c => (
          <label key={c.id} className="check"><input type="checkbox" checked={value.alert_channels.includes(c.id)} onChange={() => toggleChannel(c.id)} />{c.name}{!c.enabled && <span className="muted"> (disabled)</span>}</label>))}</div>}
        {channels.length === 0 && <p className="sm muted" style={{ marginTop: 6 }}>No channels yet. Add one under Alerts.</p>}
        <p className="sm muted" style={{ marginTop: 6 }}>A channel&apos;s own filter (Alerts page) still applies on top of this.</p>
      </div>
      <div style={{ opacity: reminderOn ? 1 : 0.55 }}>
        <div className="sm" style={{ fontWeight: 600, marginBottom: 6 }}>Remind again after</div>
        <div className="pick-row">
          <input type="number" min={0} max={20160} style={{ width: 96 }} value={minutes ?? ''} placeholder={String(lim.reminder)} disabled={!reminderOn}
            onChange={e => onChange({ ...value, alert_reminder_minutes: e.target.value === '' ? null : Math.max(0, Math.floor(Number(e.target.value))) })} aria-label="Minutes before repeating an alert" />
          <span className="sm muted">minutes</span>
          {PRESETS.map(([label, m]) => <button type="button" key={m} className={`chip-btn ${minutes === m ? 'on' : ''}`} disabled={!reminderOn} onClick={() => onChange({ ...value, alert_reminder_minutes: m })}>{label}</button>)}
          {minutes !== null && <button type="button" className="chip-btn" disabled={!reminderOn} onClick={() => onChange({ ...value, alert_reminder_minutes: null })}>Use default</button>}
        </div>
        <p className="sm muted" style={{ marginTop: 6 }}>{!reminderOn ? 'Reminders are switched off above.' : minutes === null ? `Default: every ${lim.reminder} minutes while it is still failing.` : minutes === 0 ? 'Never repeats: you are alerted once when it goes down, and once when it recovers.' : `Repeats every ${minutes >= 60 && minutes % 60 === 0 ? `${minutes / 60} hour${minutes === 60 ? '' : 's'}` : `${minutes} minutes`} while it is still failing.`}</p>
      </div>
    </fieldset>
  );
}

/** One-line summary for lists and detail pages. */
export function alertSummary(x: { alert_events?: string[]; alert_channels?: number[]; alert_reminder_minutes?: number | null }, channelNames: Map<number, string>, defaultReminder: number): string {
  const parts: string[] = [];
  parts.push(x.alert_events?.length ? x.alert_events.map(e => EVENTS.find(v => v.id === e)?.label ?? e).join(', ') : 'All alert types');
  if (x.alert_channels?.length) parts.push(`to ${x.alert_channels.map(c => channelNames.get(c) ?? `#${c}`).join(', ')}`);
  const m = x.alert_reminder_minutes ?? defaultReminder;
  if (!x.alert_events?.length || x.alert_events.includes('reminder')) parts.push(m === 0 ? 'no repeats' : `repeat every ${m >= 60 && m % 60 === 0 ? `${m / 60} h` : `${m} min`}`);
  return parts.join(' · ');
}
