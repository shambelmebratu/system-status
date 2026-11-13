'use client';

import { FormEvent, useState } from 'react';
import { Empty, Field, Icon, Modal } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import type { Channel, ScheduledMessage } from '../lib/types';

const DAYS = [['Mon', 1], ['Tue', 2], ['Wed', 3], ['Thu', 4], ['Fri', 5], ['Sat', 6], ['Sun', 7]] as const;
const WEEKDAYS = [1, 2, 3, 4, 5];
const browserZone = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; } };
const zones = (): string[] => { try { return (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf('timeZone'); } catch { return []; } };

function when(item: ScheduledMessage): string {
  const days = item.days_of_week.length === 0 || item.days_of_week.length === 7 ? 'every day'
    : item.days_of_week.join() === WEEKDAYS.join() ? 'weekdays' : item.days_of_week.map(d => DAYS[d - 1][0]).join(', ');
  return item.repeat === 'once' ? `once · ${new Date(item.run_at!).toLocaleString()}` : `${days} at ${item.time_of_day} (${item.timezone})`;
}

export function Schedules() {
  const { channels, toast, confirm } = useApp();
  const list = usePoll(() => api<ScheduledMessage[]>('/scheduled-messages'), [], 20000);
  const [editing, setEditing] = useState<ScheduledMessage | 'new' | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const items = list.value;

  async function sendNow(item: ScheduledMessage) {
    if (!(await confirm(`Send “${item.name}” now?\n\nIt goes to its channels immediately.`, { danger: false, confirmLabel: 'Send now' }))) return;
    setBusy(item.id);
    try { toast((await post<{ detail: string }>(`/scheduled-messages/${item.id}/send`)).detail); await list.reload(); } catch (e) { toast(`Send failed: ${(e as Error).message}`, true); } finally { setBusy(null); }
  }
  async function toggle(item: ScheduledMessage) {
    try { await put(`/scheduled-messages/${item.id}`, toBody(item, { enabled: !item.enabled })); await list.reload(); } catch (e) { toast((e as Error).message, true); }
  }
  async function remove(item: ScheduledMessage) {
    if (!(await confirm(`Delete “${item.name}”?\n\nThis scheduled message will no longer be sent.`))) return;
    try { await del(`/scheduled-messages/${item.id}`); toast('Deleted'); await list.reload(); } catch (e) { toast((e as Error).message, true); }
  }

  return (
    <>
      <div className="topbar"><h1>Scheduled messages</h1><span className="grow" />
        <button className="btn primary" disabled={channels.length === 0} onClick={() => setEditing('new')}><Icon name="plus" size={15} />New message</button></div>
      {channels.length === 0 && <div className="banner" style={{ marginBottom: 16 }}>Add a notification channel under <b>Alerts</b> first. Scheduled messages are delivered through those channels.</div>}
      <div className="card">
        {!items ? <p className="muted">Loading…</p> : items.length === 0 ? (
          <Empty title="No scheduled messages" action={channels.length ? <button className="btn primary" onClick={() => setEditing('new')}>Create your first message</button> : undefined}>
            Send a reminder or announcement to any channel at a fixed time, for example a daily stand-up ping at 08:58 on weekdays.
          </Empty>
        ) : (
          <table className="tbl"><thead><tr><th>Message</th><th>Schedule</th><th className="hide-sm">Channels</th><th>Next run</th><th /></tr></thead><tbody>
            {items.map(m => (
              <tr key={m.id} style={m.enabled ? undefined : { opacity: 0.55 }}>
                <td><div className="name">{m.name}<small style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.text.replace(/\n+/g, ' ')}</small></div></td>
                <td className="sm">{when(m)}</td>
                <td className="hide-sm sm">{m.channel_ids.map(id => channels.find(c => c.id === id)?.name ?? `#${id} (deleted)`).join(', ')}</td>
                <td className="sm">{m.enabled && m.next_run_at ? new Date(m.next_run_at).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : <span className="muted">{m.enabled ? 'finished' : 'paused'}</span>}
                  {m.last_status && <div className={`sm ${m.last_status === 'sent' ? 'good' : m.last_status === 'missed' ? 'warn' : 'bad'}`} title={m.last_error ?? ''}>last: {m.last_status}</div>}</td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button className="btn sm" disabled={busy === m.id} onClick={() => sendNow(m)}>{busy === m.id ? 'Sending…' : 'Send now'}</button>{' '}
                  <button className="btn sm" onClick={() => setEditing(m)}>Edit</button>{' '}
                  <button className="btn sm ghost" onClick={() => toggle(m)}>{m.enabled ? 'Pause' : 'Resume'}</button>{' '}
                  <button className="btn sm danger" onClick={() => remove(m)}>Delete</button>
                </td>
              </tr>))}
          </tbody></table>
        )}
      </div>
      {editing && <ScheduleForm existing={editing === 'new' ? undefined : editing} channels={channels} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void list.reload(); }} />}
    </>
  );
}

const toBody = (m: ScheduledMessage, over: Partial<ScheduledMessage> = {}) => {
  const x = { ...m, ...over };
  return { name: x.name, text: x.text, channel_ids: x.channel_ids, repeat: x.repeat, time_of_day: x.time_of_day, days_of_week: x.days_of_week, run_at: x.run_at, timezone: x.timezone, enabled: x.enabled };
};

/** datetime-local value (browser-local wall clock) <-> ISO */
const toLocalInput = (iso: string | null) => { if (!iso) return ''; const d = new Date(iso); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };

function ScheduleForm({ existing, channels, onClose, onSaved }: { existing?: ScheduledMessage; channels: Channel[]; onClose: () => void; onSaved: () => void }) {
  const { toast } = useApp();
  const [name, setName] = useState(existing?.name ?? '');
  const [text, setText] = useState(existing?.text ?? '');
  const [picked, setPicked] = useState<number[]>(existing?.channel_ids ?? (channels.length === 1 ? [channels[0].id] : []));
  const [repeat, setRepeat] = useState<'once' | 'daily' | 'weekly'>(existing?.repeat ?? 'weekly');
  const [time, setTime] = useState(existing?.time_of_day ?? '09:00');
  const [days, setDays] = useState<number[]>(existing?.days_of_week.length ? existing.days_of_week : WEEKDAYS);
  const [runAt, setRunAt] = useState(toLocalInput(existing?.run_at ?? null));
  const [zone, setZone] = useState(existing?.timezone ?? browserZone());
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const zoneList = zones();
  const toggleDay = (d: number) => setDays(days.includes(d) ? days.filter(x => x !== d) : [...days, d].sort());
  const togglePicked = (id: number) => setPicked(picked.includes(id) ? picked.filter(x => x !== id) : [...picked, id]);

  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    if (picked.length === 0) { setError('Choose at least one channel'); return; }
    setBusy(true);
    const body = { name, text, channel_ids: picked, repeat, time_of_day: time, days_of_week: repeat === 'weekly' ? days : [], run_at: repeat === 'once' && runAt ? new Date(runAt).toISOString() : null, timezone: zone, enabled };
    try { if (existing) await put(`/scheduled-messages/${existing.id}`, body); else await post('/scheduled-messages', body); toast(existing ? 'Schedule updated' : 'Schedule created'); onSaved(); }
    catch (caught) { setError((caught as Error).message); } finally { setBusy(false); }
  }

  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'New scheduled message'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder="Daily stand-up reminder" required autoFocus /></Field>
        <Field label="Message" hint="Markdown works in Slack, Mattermost and similar webhooks. Placeholders: {date}  {time}  {weekday}">
          <textarea rows={5} value={text} onChange={e => setText(e.target.value)} required maxLength={4000} placeholder={'👋 **Good morning team!** ☕\n@all Daily stand-up starts in **2 minutes**.\nJoin here: https://meet.google.com/…'} />
        </Field>
        <div className="field">Send to
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {channels.map(c => <label key={c.id} className="check" style={{ padding: '6px 10px', border: '1px solid var(--line-2)', borderRadius: 9, background: picked.includes(c.id) ? 'var(--surface-2)' : 'transparent' }}>
              <input type="checkbox" checked={picked.includes(c.id)} onChange={() => togglePicked(c.id)} />{c.name} <span className="muted sm">{c.type}</span>{!c.enabled && <span className="warn sm">disabled</span>}</label>)}
          </div>
        </div>
        <div className="form-grid">
          <Field label="Repeat"><select value={repeat} onChange={e => setRepeat(e.target.value as typeof repeat)}><option value="weekly">On selected days</option><option value="daily">Every day</option><option value="once">Once</option></select></Field>
          {repeat === 'once'
            ? <Field label="Date & time (your browser’s time zone)"><input type="datetime-local" value={runAt} onChange={e => setRunAt(e.target.value)} required /></Field>
            : <Field label="Time of day"><input type="time" value={time} onChange={e => setTime(e.target.value)} required /></Field>}
          {repeat !== 'once' && <Field label="Time zone"><input list="zones" value={zone} onChange={e => setZone(e.target.value)} required /><datalist id="zones">{zoneList.map(z => <option key={z} value={z} />)}</datalist></Field>}
        </div>
        {repeat === 'weekly' && (
          <div className="seg" style={{ alignSelf: 'flex-start' }} role="group" aria-label="Days of week">
            {DAYS.map(([label, d]) => <button type="button" key={d} className={days.includes(d) ? 'on' : ''} aria-pressed={days.includes(d)} onClick={() => toggleDay(d)}>{label}</button>)}
          </div>
        )}
        <label className="check"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Enabled</label>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : existing ? 'Save changes' : 'Create schedule'}</button></div>
      </form>
    </Modal>
  );
}
