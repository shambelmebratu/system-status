'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import { Empty, Field, Icon } from '../components/ui';
import { AiSettings, Markdown, providerOf } from '../components/ai';
import { api, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

type Msg = { role: 'user' | 'assistant'; content: string; tools?: { tool: string }[]; model?: string };
const SUGGESTIONS = ['Which services had the most downtime this week?', 'Is anything unhealthy right now?', 'Which server is closest to running out of disk?',
  'Summarise the incidents of the last 24 hours', 'How are our SLOs doing?', 'Any security problems I should fix first?'];
const CHAT_KEY = 'smw.ai.chat';

function NotReady({ settings }: { settings: AiSettings | null }) {
  const { isAdmin, go } = useApp();
  if (!settings) return <p className="muted">Loading…</p>;
  return <div className="card"><Empty title="AI is not set up">
    {!settings.enabled ? 'AI features are turned off.' : `${providerOf(settings)?.label ?? 'The AI provider'} is not fully configured (API key, model or address missing).`} {isAdmin ? <button className="lg-link" onClick={() => go('ai-settings')}>Open AI settings</button> : 'Ask an admin to set it up.'}
    <br /><span className="sm muted">Anomaly detection works without AI.</span>
  </Empty></div>;
}

export function Assistant() {
  const settings = usePoll(() => api<AiSettings>('/ai/settings'), [], 0).value ?? null;
  const { toast } = useApp();
  const [messages, setMessages] = useState<Msg[]>(() => { try { return JSON.parse(sessionStorage.getItem(CHAT_KEY) ?? '[]'); } catch { return []; } });
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { try { sessionStorage.setItem(CHAT_KEY, JSON.stringify(messages.slice(-30))); } catch { /* storage unavailable */ } end.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  async function send(text: string) {
    const q = text.trim();
    if (!q || busy) return;
    const next: Msg[] = [...messages, { role: 'user', content: q }];
    setMessages(next); setInput(''); setBusy(true);
    try {
      const r = await post<{ answer: string; tools: { tool: string }[]; model: string }>('/ai/ask', { messages: next.slice(-20).map(({ role, content }) => ({ role, content })) });
      setMessages([...next, { role: 'assistant', content: r.answer, tools: r.tools, model: r.model }]);
    } catch (e) { toast((e as Error).message, true); setMessages(messages); setInput(q); } finally { setBusy(false); }
  }
  const submit = (e: FormEvent) => { e.preventDefault(); void send(input); };

  return <>
    <div className="topbar"><div><h1>Ask your infrastructure</h1><p className="muted sm">Questions in plain words, answered from SM-Watch's own data. The AI only sees the monitors you can see.</p></div>
      <span className="grow" />{messages.length > 0 && <button className="btn ghost sm" onClick={() => setMessages([])}>New conversation</button>}</div>
    {!settings?.ready ? <NotReady settings={settings} /> : <div className="card chat">
      <div className="chat-log">
        {messages.length === 0 && <div className="chat-empty"><p className="muted">Try one of these:</p><div className="chat-sugg">{SUGGESTIONS.map(s => <button key={s} className="btn ghost sm" onClick={() => void send(s)}>{s}</button>)}</div></div>}
        {messages.map((m, i) => <div key={i} className={`chat-msg ${m.role}`}>
          {m.role === 'user' ? <p>{m.content}</p> : <><Markdown text={m.content} />
            {m.tools && m.tools.length > 0 && <div className="sm muted chat-tools">Looked at: {[...new Set(m.tools.map(t => t.tool.replace(/_/g, ' ')))].join(', ')} · {m.model}</div>}</>}
        </div>)}
        {busy && <div className="chat-msg assistant"><p className="muted">Looking into it…</p></div>}
        <div ref={end} />
      </div>
      <form className="chat-input" onSubmit={submit}>
        <textarea value={input} onChange={e => setInput(e.target.value)} placeholder="Ask about uptime, incidents, servers, SLOs, security…" rows={2} maxLength={8000}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(input); } }} aria-label="Your question" />
        <button className="btn primary" disabled={busy || !input.trim()}>Ask</button>
      </form>
      <p className="sm muted" style={{ margin: '6px 12px 10px' }}>Your question and the data the AI looks up are sent to {providerOf(settings)?.destination ?? 'the AI provider'}. AI can be wrong: check important answers.</p>
    </div>}
  </>;
}

type Anomaly = { id: number; target_type: string; target_id: number; target_name: string; metric: string; label: string; direction: string; score: number; description: string;
  started_at: string; last_seen_at: string; resolved_at: string | null; alerted: boolean };

export function Anomalies() {
  const { go } = useApp();
  const { value, error } = usePoll(() => api<Anomaly[]>('/anomalies?hours=168'), [], 60000);
  const open = (value ?? []).filter(a => !a.resolved_at), past = (value ?? []).filter(a => a.resolved_at);
  const row = (a: Anomaly) => <article key={a.id} className={`inc ${a.resolved_at ? 'resolved' : 'warning'}`} tabIndex={0} onClick={() => go(`${a.target_type}s/${a.target_id}`)} onKeyDown={e => e.key === 'Enter' && go(`${a.target_type}s/${a.target_id}`)}>
    <span className="inc-ico"><Icon name={a.resolved_at ? 'check' : 'zap'} size={18} /></span>
    <div className="inc-main"><div className="inc-title"><b>{a.target_name}</b><span className="tag">{a.label}</span>{a.alerted && <span className="tag">alerted</span>}</div><div className="inc-what">{a.description}</div></div>
    <div className="inc-side"><span className={`inc-state ${a.resolved_at ? 'resolved' : 'warning'}`}><i />{a.resolved_at ? 'Back to normal' : 'Ongoing'}</span>
      <span className="inc-time" title={new Date(a.started_at).toLocaleString()}>{timeAgo(a.started_at)}</span></div>
  </article>;
  return <>
    <div className="topbar"><div><h1>Anomalies</h1><p className="muted sm">Metrics far outside their own normal range of the last 7 days: CPU, memory, load and network of servers, and response time of services. Plain statistics: no AI key needed, nothing leaves this server.</p></div></div>
    {error && !value ? <div className="err">{error}</div> : !value ? <p className="muted">Loading…</p> : value.length === 0
      ? <div className="card"><Empty title="Nothing unusual">Every metric is within its normal range. Detection needs about a day of history per monitor before it starts judging.</Empty></div>
      : <>{open.length > 0 && <section className="inc-group"><h2 className="inc-day">Ongoing<span>{open.length}</span></h2><div className="inc-list">{open.map(row)}</div></section>}
        {past.length > 0 && <section className="inc-group"><h2 className="inc-day">Last 7 days<span>{past.length}</span></h2><div className="inc-list">{past.map(row)}</div></section>}</>}
  </>;
}

export function AiSettingsView() {
  const { isAdmin, toast } = useApp();
  const { value, reload } = usePoll(() => api<AiSettings>('/ai/settings'), [], 0);
  const [form, setForm] = useState<AiSettings | null>(null);
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (value) setForm(value); }, [value]);
  if (!form) return <p className="muted">Loading…</p>;
  const set = (patch: Partial<AiSettings>) => setForm({ ...form, ...patch });
  const p = providerOf(form);
  const saved = value?.provider === form.provider;            // key status shown is for the provider that is saved
  const keyState = p?.key_in_env ? 'env' : p?.key_saved ? 'dashboard' : null;
  function pick(id: string) {
    const next = form!.providers.find(x => x.id === id);
    setKey('');
    set({ provider: id, model: next?.default_model ?? '', base_url: next?.base_url_editable ? next.default_base_url : '' });
  }
  async function save(extra: { clear_key?: boolean } = {}) {
    if (!form) return;
    setBusy(true);
    try {
      const { enabled, provider, model, base_url, auto_explain, post_explanations, allow_logs, anomaly_alerts, auto_per_hour } = form;
      await put('/ai/settings', { enabled, provider, model, base_url, auto_explain, post_explanations, allow_logs, anomaly_alerts, auto_per_hour, api_key: key, ...extra });
      setKey(''); toast('AI settings saved'); await reload();
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  async function test() {
    setBusy(true);
    try { const r = await post<{ model: string }>('/ai/test'); toast(`Connected: ${r.model} answered`); await reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  const box = (k: keyof AiSettings, label: string, hint: string) => <label className="check"><input type="checkbox" disabled={!isAdmin} checked={Boolean(form[k])} onChange={e => set({ [k]: e.target.checked } as Partial<AiSettings>)} /><span>{label}<span className="sm muted"> — {hint}</span></span></label>;
  const keyHint = !p ? '' : keyState === 'env' ? `Set by ${p.key_env} in .env (that takes precedence).`
    : keyState === 'dashboard' ? 'A key is saved (encrypted). Type a new one to replace it.'
    : `${p.needs_key ? 'Required.' : 'Optional.'}${p.key_prefix ? ` Usually starts with ${p.key_prefix}.` : ''}${p.key_env ? ` Or set ${p.key_env} in .env.` : ''}`;
  return <>
    <div className="topbar"><div><h1>AI settings</h1><p className="muted sm">Choose who answers: the free provider needs no key, or use your own key with Anthropic, OpenAI, Gemini, Groq, OpenRouter, Mistral or DeepSeek, or run models privately with Ollama. Usage is billed by the provider you choose.</p></div></div>
    <div className="card form-card" style={{ maxWidth: 760 }}>
      {box('enabled', 'Turn on AI features', 'incident explanations, log analysis and the assistant')}
      <Field label="Provider" hint={p?.free || undefined}>
        <select value={form.provider} onChange={e => pick(e.target.value)} disabled={!isAdmin}>
          {form.providers.map(x => <option key={x.id} value={x.id}>{x.label}</option>)}
        </select>
      </Field>
      {p?.id === 'free' && <p className="sm muted" style={{ margin: '0 0 10px' }}>The free provider answers simple requests well. It is slower and limited to about one reply every 45 seconds, and the assistant answers from one data snapshot instead of looking things up step by step. Data goes to a public free service, so for confidential infrastructure pick Ollama (local) or a provider with your own key.</p>}
      {p?.accepts_key && <Field label="API key" hint={<>{keyHint}{p.key_url && <> <a href={p.key_url} target="_blank" rel="noreferrer">Get a key</a></>}</>}>
        <input type="password" value={key} onChange={e => setKey(e.target.value)} disabled={!isAdmin || keyState === 'env'} placeholder={keyState ? '•••••••• (saved)' : p.key_prefix ? `${p.key_prefix}…` : ''} autoComplete="off" />
      </Field>}
      {p?.base_url_editable && <Field label="Base URL" hint={p.id === 'ollama' ? 'Where Ollama listens, ending in /v1. Inside Docker Compose use http://ollama:11434/v1; on the host, http://host.docker.internal:11434/v1.' : 'The OpenAI-compatible API address, usually ending in /v1.'}>
        <input value={form.base_url} onChange={e => set({ base_url: e.target.value })} disabled={!isAdmin} placeholder={p.default_base_url || 'https://host/v1'} />
      </Field>}
      <Field label="Model" hint={p?.default_model ? `Default ${p.default_model}.` : 'Required for this provider.'}><input value={form.model} onChange={e => set({ model: e.target.value })} disabled={!isAdmin} placeholder={p?.default_model} /></Field>
      {box('auto_explain', 'Explain new incidents automatically', 'about 2 minutes after an incident opens')}
      <Field label="Automatic explanations per hour (limit)"><input type="number" min={1} max={60} value={form.auto_per_hour} onChange={e => set({ auto_per_hour: Number(e.target.value) })} disabled={!isAdmin} /></Field>
      {box('post_explanations', 'Post automatic explanations to alert channels', 'as a follow-up message')}
      {box('allow_logs', 'Allow "Analyze with AI" in the log viewer', 'operators send the lines shown, with secrets masked')}
      {box('anomaly_alerts', 'Send alerts for anomalies', 'no AI involved; uses the normal alert channels')}
      <div className="sm muted" style={{ margin: '10px 0' }}>
        <b>What is sent to {p?.destination ?? 'the provider'}:</b> for an explanation, the incident, its monitor's recent checks and metrics, other incidents around then, and recent SM-Watch configuration changes; for log analysis, the log lines shown; for the assistant, your question and the data it looks up. Recognisable secrets are masked first.
      </div>
      <p className="sm">This month ({form.month}): <b>{form.usage.requests}</b> requests · {form.usage.input_tokens.toLocaleString()} input tokens · {form.usage.output_tokens.toLocaleString()} output tokens</p>
      {isAdmin && <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="btn primary" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</button>
        <button className="btn" disabled={busy || !value?.ready || !saved} title={!saved ? 'Save first' : undefined} onClick={() => void test()}>Test connection</button>
        {keyState === 'dashboard' && saved && <button className="btn ghost" disabled={busy} onClick={() => void save({ clear_key: true })}>Remove saved key</button>}
      </div>}
    </div>
  </>;
}
