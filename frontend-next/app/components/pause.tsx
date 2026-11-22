'use client';

import { FormEvent, useState } from 'react';
import { post } from '../lib/api';
import { useApp } from '../lib/app';
import { Field, Icon, Modal, StatusPill } from './ui';

type Pausable = { id: number; name: string; paused?: 'monitor' | 'alerts' | null; paused_until?: string | null; paused_by?: string | null; pause_reason?: string | null };

const DURATIONS: [string, number | null][] = [['15 minutes', 15], ['1 hour', 60], ['4 hours', 240], ['8 hours', 480], ['24 hours', 1440], ['7 days', 10080], ['Until a date and time…', -1], ['Until I resume it', null]];

function until(iso: string | null | undefined) {
  if (!iso) return 'until resumed';
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return `until ${sameDay ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : d.toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}`;
}

/** "Paused · until 14:30" for lists and headers. */
export function PausedBadge({ item }: { item: Pausable }) {
  if (!item.paused) return null;
  return <span className="tag paused-tag" title={`${item.paused === 'monitor' ? 'Not checked and no alerts' : 'Checked, but alerts are muted'}${item.paused_by ? ` · paused by ${item.paused_by}` : ''}${item.pause_reason ? ` · ${item.pause_reason}` : ''}`}>
    <Icon name="pause" size={10} /> {item.paused === 'monitor' ? 'Paused' : 'Muted'} · {until(item.paused_until)}</span>;
}

/** The status pill, or "Paused" while monitoring is paused (its last status is stale then), plus the paused / muted badge. */
export function MonitorStatus({ item }: { item: Pausable & { last_status: string } }) {
  if (item.paused === 'monitor') return <span className="status-cell" title={`Not checked and no alerts${item.paused_by ? ` · paused by ${item.paused_by}` : ''}${item.pause_reason ? ` · ${item.pause_reason}` : ''}`}>
    <StatusPill status="unknown" label={`Paused · ${until(item.paused_until)}`} /></span>;
  return <span className="status-cell"><StatusPill status={item.last_status} /><PausedBadge item={item} /></span>;
}

/** Pause / Resume button for a server or service page header. */
export function PauseControl({ kind, item }: { kind: 'servers' | 'services'; item: Pausable }) {
  const { canOperate, toast, refresh } = useApp();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  if (!canOperate) return null;
  async function resume() {
    setBusy(true);
    try { await post(`/${kind}/${item.id}/resume`); toast(`${item.name} resumed`); await refresh(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  if (item.paused) return <button className="btn sm" onClick={resume} disabled={busy}><Icon name="play" size={13} />{busy ? 'Resuming…' : 'Resume'}</button>;
  return <>
    <button className="btn sm" onClick={() => setOpen(true)} title="Stop checks and alerts for a while"><Icon name="pause" size={13} />Pause</button>
    {open && <PauseDialog kind={kind} item={item} onClose={() => setOpen(false)} />}
  </>;
}

function PauseDialog({ kind, item, onClose }: { kind: 'servers' | 'services'; item: Pausable; onClose: () => void }) {
  const { toast, refresh } = useApp();
  const [mode, setMode] = useState<'monitor' | 'alerts'>('monitor');
  const [duration, setDuration] = useState<string>('60');
  const [at, setAt] = useState(() => { const d = new Date(Date.now() + 2 * 3600e3); d.setMinutes(0, 0, 0); return new Date(d.getTime() - d.getTimezoneOffset() * 60e3).toISOString().slice(0, 16); });
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    const body: Record<string, unknown> = { mode, reason };
    if (duration === '-1') body.until = new Date(at).toISOString();
    else if (duration !== 'null') body.minutes = Number(duration);
    try { await post(`/${kind}/${item.id}/pause`, body); toast(`${item.name} ${mode === 'monitor' ? 'paused' : 'muted'}`); await refresh(); onClose(); }
    catch (caught) { setError((caught as Error).message); } finally { setBusy(false); }
  }
  return (
    <Modal title={`Pause ${item.name}`} onClose={onClose}>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="pause-modes">
          <label className={`pause-mode ${mode === 'monitor' ? 'on' : ''}`}><input type="radio" checked={mode === 'monitor'} onChange={() => setMode('monitor')} />
            <b>Pause monitoring</b><span className="muted sm">No checks and no alerts. Nothing is recorded, so the time does not count against uptime.</span></label>
          <label className={`pause-mode ${mode === 'alerts' ? 'on' : ''}`}><input type="radio" checked={mode === 'alerts'} onChange={() => setMode('alerts')} />
            <b>Mute alerts only</b><span className="muted sm">Keep checking and recording, but send no alerts. Problems still show on the dashboard.</span></label>
        </div>
        <div className="form-grid">
          <Field label="For how long"><select value={duration} onChange={e => setDuration(e.target.value)}>{DURATIONS.map(([label, m]) => <option key={label} value={String(m)}>{label}</option>)}</select></Field>
          {duration === '-1' && <Field label="Resume at (your time)"><input type="datetime-local" value={at} onChange={e => setAt(e.target.value)} required /></Field>}
        </div>
        <Field label="Reason" hint="Optional. Shown on the monitor and written to the audit log."><input value={reason} onChange={e => setReason(e.target.value)} maxLength={200} placeholder="Server migration" /></Field>
        <p className="muted sm" style={{ margin: 0 }}>{duration === 'null' ? 'It stays paused until someone presses Resume.' : 'It resumes by itself. You can also resume it earlier.'} For planned work announced on the status page, use a maintenance window instead.</p>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Pausing…' : mode === 'monitor' ? 'Pause' : 'Mute alerts'}</button></div>
      </form>
    </Modal>
  );
}
