'use client';

import { FormEvent, useState } from 'react';
import { Empty, Field, Icon, Modal } from '../components/ui';
import { del, post, put } from '../lib/api';
import { useApp } from '../lib/app';
import { timeAgo } from '../lib/format';
import type { Channel, ChannelType } from '../lib/types';

const LABEL: Record<ChannelType, string> = { telegram: 'Telegram', slack: 'Slack', webhook: 'Webhook', whatsapp: 'WhatsApp Cloud API' };
const HELP: Record<ChannelType, string> = {
  telegram: 'Create a bot with @BotFather, add it to your chat, then open https://api.telegram.org/bot<token>/getUpdates to find the chat ID (group IDs are negative).',
  slack: 'Create an Incoming Webhook in your Slack app settings and paste the https://hooks.slack.com/… URL.',
  webhook: 'Receives a JSON POST: { source, text, sent_at }. An optional token is sent as a Bearer Authorization header.',
  whatsapp: 'Uses the Meta WhatsApp Cloud API with an approved Utility template that has one body variable.',
};

const EVENTS: { id: string; label: string; hint: string }[] = [
  { id: 'down', label: 'Down', hint: 'A server, service or cluster stopped responding' },
  { id: 'alert', label: 'Over a limit', hint: 'CPU, memory, disk, a process or a cluster problem crossed its threshold' },
  { id: 'recovered', label: 'Recovered', hint: 'It is healthy again' },
  { id: 'reminder', label: 'Reminders', hint: 'Repeats while something is still failing' },
];
const KINDS: { id: string; label: string }[] = [{ id: 'server', label: 'Servers' }, { id: 'service', label: 'Services' }, { id: 'cluster', label: 'Kubernetes clusters' }];
/** An empty selection means "everything", which is also how the form shows it (all ticked). */
const allOr = (chosen: string[] | undefined, all: string[]) => (chosen && chosen.length ? chosen : all);
function routingSummary(c: Channel): string {
  const events = c.notify_events?.length ? c.notify_events.map(e => EVENTS.find(x => x.id === e)?.label ?? e).join(', ') : 'All alerts';
  const kinds = c.notify_kinds?.length ? c.notify_kinds.map(k => KINDS.find(x => x.id === k)?.label ?? k).join(', ') : 'everything';
  return `${events} · ${kinds.toLowerCase()}`;
}

const plainAlert = (m: string) => m.replace(/<\/?b>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

export function Channels() {
  const { channels, data, refresh, toast, confirm } = useApp();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Channel | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  async function test(id: number) {
    setBusy(id);
    try { toast((await post<{ detail: string }>(`/channels/${id}/test`)).detail || 'Test sent'); } catch (e) { toast(`Test failed: ${(e as Error).message}`, true); } finally { setBusy(null); }
  }
  async function remove(id: number, name: string) {
    if (!(await confirm(`Remove channel ${name}?\n\nAlerts will no longer be sent to it.`))) return;
    try { await del(`/channels/${id}`); toast('Channel removed'); await refresh(); } catch (e) { toast((e as Error).message, true); }
  }

  return (
    <>
      <div className="topbar"><h1>Alerts</h1><span className="grow" /><button className="btn primary" onClick={() => setAdding(true)}><Icon name="plus" size={15} />Add channel</button></div>
      <div className="grid g-side">
        <section className="card"><div className="card-head"><h2>Notification channels</h2></div>
          {channels.length === 0 ? <Empty title="No channels">Alerts are recorded but not delivered until you add a channel.</Empty> : (
            <table className="tbl"><tbody>{channels.map(c => (
              <tr key={c.id}><td><div className="name">{c.name}<small>{LABEL[c.type]}{c.chat_id ? ` · ${c.chat_id}` : ''}{!c.enabled && ' · disabled'}</small><small>Receives: {routingSummary(c)}</small></div></td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}><button className="btn sm" disabled={busy === c.id} onClick={() => test(c.id)}>{busy === c.id ? 'Sending…' : 'Send test'}</button> <button className="btn sm" onClick={() => setEditing(c)}>Edit</button> <button className="btn sm danger" onClick={() => remove(c.id, c.name)}>Remove</button></td></tr>))}</tbody></table>
          )}
        </section>
        <section className="card"><div className="card-head"><h2>Delivery log</h2></div>
          {!data?.events.length ? <p className="muted sm">No alerts yet.</p> : <div className="timeline">{data.events.map(e => (
            <div key={e.id} className="tl-item"><span className={`tl-dot ${e.severity === 'critical' ? 'critical' : 'resolved'}`} />
              <div className="tl-body"><div className="sm" style={{ whiteSpace: 'pre-line' }}>{plainAlert(e.message)}</div>
                <div className="tl-meta">{timeAgo(e.created_at)} · {e.sent ? <span className="good">delivered</span> : e.delivery_error?.startsWith('Not sent:') ? <span className="muted">not sent (no channel is set to receive this kind)</span> : <span className="bad">not delivered{e.delivery_error ? ` (${e.delivery_error})` : ''} · {e.delivery_attempts} attempts</span>}</div></div></div>))}</div>}
        </section>
      </div>
      {adding && <ChannelForm onClose={() => setAdding(false)} />}
      {editing && <ChannelForm existing={editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function ChannelForm({ existing, onClose }: { existing?: Channel; onClose: () => void }) {
  const { toast, refresh } = useApp();
  const [type, setType] = useState<ChannelType>(existing?.type ?? 'telegram');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const keep = existing && existing.type === type ? 'Leave blank to keep the saved value' : undefined;
  const [f, setF] = useState({ name: existing?.name ?? '', token: '', chat_id: existing?.chat_id ?? '', endpoint: '', phone_number_id: existing?.phone_number_id ?? '', template_name: existing?.template_name ?? 'smwatch_alert', template_language: 'en_US' });
  const [events, setEvents] = useState<string[]>(allOr(existing?.notify_events, EVENTS.map(e => e.id)));
  const [kinds, setKinds] = useState<string[]>(allOr(existing?.notify_kinds, KINDS.map(k => k.id)));
  const toggle = (list: string[], set: (v: string[]) => void, id: string) => set(list.includes(id) ? list.filter(x => x !== id) : [...list, id]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [found, setFound] = useState<{ bot: string; chats: { id: number; type: string; title: string }[] } | null>(null);
  const [finding, setFinding] = useState(false);
  async function findChats() {
    setFinding(true); setError(''); setFound(null);
    try { setFound(await post('/channels/telegram/discover', { token: f.token })); } catch (caught) { setError((caught as Error).message); } finally { setFinding(false); }
  }
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!events.length || !kinds.length) { setError('Tick at least one alert type and one source, or disable the channel instead.'); return; }
    setBusy(true); setError('');
    const body = { ...f, type, enabled, notify_events: events, notify_kinds: kinds };
    try {
      if (existing) await put(`/channels/${existing.id}`, body); else await post('/channels', body);
      toast(existing ? 'Channel updated. Use “Send test” to verify.' : `${LABEL[type]} channel saved. Use “Send test” to verify.`); await refresh(); onClose();
    }
    catch (caught) { setError((caught as Error).message); } finally { setBusy(false); }
  }

  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'Add notification channel'} onClose={onClose}>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="seg" style={{ alignSelf: 'flex-start', flexWrap: 'wrap' }}>{(Object.keys(LABEL) as ChannelType[]).map(t => <button type="button" key={t} className={type === t ? 'on' : ''} onClick={() => setType(t)}>{LABEL[t]}</button>)}</div>
        <p className="muted sm">{HELP[type]}</p>
        <div className="form-grid">
          <Field label="Name"><input value={f.name} onChange={set('name')} placeholder="On-call" required autoFocus /></Field>
          {type === 'telegram' && <><Field label="Bot token" hint={keep}><input type="password" value={f.token} onChange={set('token')} required={!keep} placeholder={keep ? '••••••••  (saved)' : undefined} /></Field><Field label="Chat / group ID"><input value={f.chat_id} onChange={set('chat_id')} required /></Field></>}
          {(type === 'slack' || type === 'webhook') && <Field label="Webhook URL" hint={keep}><input type="url" value={f.endpoint} onChange={set('endpoint')} required={!keep} placeholder={keep ? '(saved)' : undefined} /></Field>}
          {type === 'webhook' && <Field label="Bearer token (optional)" hint={keep}><input type="password" value={f.token} onChange={set('token')} /></Field>}
          {type === 'whatsapp' && <>
            <Field label="Access token" hint={keep}><input type="password" value={f.token} onChange={set('token')} required={!keep} /></Field>
            <Field label="Phone number ID"><input value={f.phone_number_id} onChange={set('phone_number_id')} required /></Field>
            <Field label="Recipient number"><input value={f.chat_id} onChange={set('chat_id')} placeholder="15551234567" required /></Field>
            <Field label="Template name"><input value={f.template_name} onChange={set('template_name')} required /></Field>
            <Field label="Template language"><input value={f.template_language} onChange={set('template_language')} /></Field></>}
        </div>
        <fieldset className="pick">
          <legend>Send to this channel</legend>
          <div className="pick-grid">{EVENTS.map(e => (
            <label key={e.id} className={`pick-item ${events.includes(e.id) ? 'on' : ''}`}><input type="checkbox" checked={events.includes(e.id)} onChange={() => toggle(events, setEvents, e.id)} /><span><b>{e.label}</b><small>{e.hint}</small></span></label>))}</div>
          <div className="pick-row"><span className="sm muted">From</span>{KINDS.map(k => (
            <label key={k.id} className="check"><input type="checkbox" checked={kinds.includes(k.id)} onChange={() => toggle(kinds, setKinds, k.id)} />{k.label}</label>))}</div>
        </fieldset>
        <label className="check"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Enabled (disabled channels receive no alerts)</label>
        {type === 'telegram' && (
          <div className="card" style={{ background: 'var(--bg)', boxShadow: 'none' }}>
            <div className="card-head" style={{ marginBottom: 8 }}><h3>Find chat ID</h3><span className="grow" /><button type="button" className="btn sm" disabled={finding || f.token.length < 10} onClick={findChats}>{finding ? 'Looking…' : 'Find chats'}</button></div>
            <p className="sm muted">Add the bot to your group (as admin for channels), send any message there, then click Find chats and pick it.</p>
            {found && (found.chats.length === 0
              ? <p className="sm warn" style={{ marginTop: 8 }}>Bot @{found.bot} is valid but hasn’t seen any chats yet. Send a message in the group (e.g. “/start@{found.bot}”) and try again.</p>
              : <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>{found.chats.map(c => <button type="button" key={c.id} className="btn sm" style={{ justifyContent: 'space-between' }} onClick={() => setF({ ...f, chat_id: String(c.id) })}><span>{c.title} <span className="muted">· {c.type}</span></span><code>{c.id}</code></button>)}</div>)}
          </div>
        )}
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : existing ? 'Save changes' : 'Save channel'}</button></div>
      </form>
    </Modal>
  );
}
