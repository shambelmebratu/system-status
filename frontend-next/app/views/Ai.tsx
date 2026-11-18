'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import { Empty, Field, Icon } from '../components/ui';
import { AiFeature, AiProvider, AiSettings, Feature, Markdown, SharedBadge, Tier, providerOf } from '../components/ai';
import { api, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

type Msg = { role: 'user' | 'assistant'; content: string; tools?: { tool: string }[]; model?: string; tier?: string };
const SUGGESTIONS = ['Which services had the most downtime this week?', 'Is anything unhealthy right now?', 'Which server is closest to running out of disk?',
  'Summarise the incidents of the last 24 hours', 'How are our SLOs doing?', 'Any security problems I should fix first?'];
const CHAT_KEY = 'smw.ai.chat';

function NotReady({ settings }: { settings: AiSettings | null }) {
  const { isAdmin, go } = useApp();
  if (!settings) return <p className="muted">Loading…</p>;
  return <div className="card"><Empty title="AI is not set up">
    {settings.features.assistant.problem} {isAdmin ? <button className="lg-link" onClick={() => go('ai-settings')}>Open AI settings</button> : 'Ask an admin to set it up.'}
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
      const r = await post<{ answer: string; tools: { tool: string }[]; model: string; tier: string }>('/ai/ask', { messages: next.slice(-20).map(({ role, content }) => ({ role, content })) });
      setMessages([...next, { role: 'assistant', content: r.answer, tools: r.tools, model: r.model, tier: r.tier }]);
    } catch (e) { toast((e as Error).message, true); setMessages(messages); setInput(q); } finally { setBusy(false); }
  }
  const submit = (e: FormEvent) => { e.preventDefault(); void send(input); };

  return <>
    <div className="topbar"><div><h1>Ask your infrastructure</h1><p className="muted sm">Questions in plain words, answered from SM-Watch's own data. The AI only sees the monitors you can see.</p></div>
      <span className="grow" />{messages.length > 0 && <button className="btn ghost sm" onClick={() => setMessages([])}>New conversation</button>}</div>
    {!settings?.features.assistant.ready ? <NotReady settings={settings} /> : <div className="card chat">
      <div className="chat-log">
        {messages.length === 0 && <div className="chat-empty"><p className="muted">Try one of these:</p><div className="chat-sugg">{SUGGESTIONS.map(s => <button key={s} className="btn ghost sm" onClick={() => void send(s)}>{s}</button>)}</div></div>}
        {messages.map((m, i) => <div key={i} className={`chat-msg ${m.role}`}>
          {m.role === 'user' ? <p>{m.content}</p> : <><Markdown text={m.content} />
            {m.tools && m.tools.length > 0 && <div className="sm muted chat-tools">Looked at: {[...new Set(m.tools.map(t => t.tool.replace(/_/g, ' ')))].join(', ')} · {m.model} <SharedBadge tier={m.tier} /></div>}</>}
        </div>)}
        {busy && <div className="chat-msg assistant"><p className="muted">Looking into it…</p></div>}
        <div ref={end} />
      </div>
      <form className="chat-input" onSubmit={submit}>
        <textarea value={input} onChange={e => setInput(e.target.value)} placeholder="Ask about uptime, incidents, servers, SLOs, security…" rows={2} maxLength={8000}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(input); } }} aria-label="Your question" />
        <button className="btn primary" disabled={busy || !input.trim()}>Ask</button>
      </form>
      <p className="sm muted" style={{ margin: '6px 12px 10px' }}>Your question and the data the AI looks up are sent to {settings.features.assistant.destination ?? 'the AI provider'}{settings.features.assistant.tier === 'dev' ? ' through the Development tier: the provider may log, retain or train on it, and security findings are left out' : ''}. AI can be wrong: check important answers.</p>
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

const TIER_INFO: Record<Tier, { title: string; tag: string; text: string }> = {
  dev: { title: 'Development / Testing tier', tag: 'Free · shared data',
    text: 'For testing and non-sensitive work with free keys or keyless public endpoints. Data sent through this tier may be logged, retained, or used by the provider to train its models.' },
  confidential: { title: 'Confidential / Production tier', tag: 'Zero data retention',
    text: 'For server logs, incidents and security data. Only providers that run locally or offer zero data retention and no training (paid or enterprise plans) are allowed, and an admin must confirm the account terms.' },
};

/** One tier: on/off, provider (with its data-handling terms), key, address, model, and the zero-retention confirmation. */
function TierCard({ tier, form, saved, isAdmin, keyValue, setKey, setTier, onTest, onClearKey, onModels, models, busy }: {
  tier: Tier; form: AiSettings; saved: AiSettings; isAdmin: boolean; keyValue: string; setKey: (v: string) => void; setTier: (patch: Record<string, unknown>) => void;
  onTest: () => void; onClearKey: (provider: string) => void; onModels: () => void; models: string[]; busy: boolean }) {
  const t = form.tiers[tier];
  const p = providerOf(form, tier) as AiProvider;
  const info = TIER_INFO[tier];
  const savedSame = saved.tiers[tier].provider === t.provider;
  const keyState = p.key_in_env ? 'env' : p.key_saved ? 'dashboard' : null;
  const choices = form.providers.filter(x => tier === 'dev' || x.privacy !== 'shared');
  const needsConfirm = tier === 'confidential' && p.privacy === 'zdr_possible';
  const confirmed = needsConfirm && savedSame && !!saved.tiers.confidential.zdr_confirmed_at;
  const keyHint = keyState === 'env' ? `Set by ${p.key_env} in .env (that takes precedence).` : keyState === 'dashboard' ? 'A key is saved (encrypted). Type a new one to replace it.'
    : `${p.needs_key ? 'Required.' : 'Optional.'}${p.key_prefix ? ` Usually starts with ${p.key_prefix}.` : ''}${p.key_env ? ` Or set ${p.key_env} in .env.` : ''}`;
  return (
    <section className={`card form-card ai-tier ${tier}`}>
      <div className="card-head"><h2>{info.title}</h2><span className={`ai-tier-tag ${tier}`}>{info.tag}</span><span className="grow" />
        {savedSame && saved.tiers[tier].ready ? <span className="tag good">ready</span> : <span className="tag">{saved.tiers[tier].enabled ? 'not ready' : 'off'}</span>}</div>
      <p className="sm muted" style={{ marginTop: 0 }}>{info.text}</p>
      {tier === 'dev' && <div className="ai-warn" role="note"><Icon name="alert" size={15} /><span><b>Shared data.</b> Anything sent through this tier may be logged, retained, or used by the provider for model training. Do not route production logs, incidents or security reports here.</span></div>}
      <label className="check"><input type="checkbox" disabled={!isAdmin} checked={t.enabled} onChange={e => setTier({ enabled: e.target.checked })} /><span>Turn on the {tier === 'dev' ? 'Development' : 'Confidential'} tier</span></label>
      <Field label="Provider" hint={p.free || undefined}>
        <select value={t.provider} disabled={!isAdmin} onChange={e => { const next = form.providers.find(x => x.id === e.target.value); setTier({ provider: e.target.value, model: next?.default_model ?? '', base_url: next?.base_url_editable ? next.default_base_url : '' }); }}>
          {choices.map(x => <option key={x.id} value={x.id}>{x.label}{x.privacy === 'local' ? ' · local' : x.privacy === 'shared' ? ' · shared data' : ''}</option>)}
        </select>
      </Field>
      <div className={`ai-policy ${p.privacy}`}><b>{p.privacy === 'local' ? 'Stays on your network' : p.privacy === 'shared' ? 'Provider may keep or reuse data' : 'Zero retention on paid plans'}:</b> {p.policy}
        {p.policy_url && <> <a href={p.policy_url} target="_blank" rel="noreferrer">Provider terms</a></>}</div>
      {tier === 'confidential' && form.providers.some(x => x.privacy === 'shared') && <p className="sm muted" style={{ margin: '0 0 8px' }}>Providers whose terms allow data reuse ({form.providers.filter(x => x.privacy === 'shared').map(x => x.label.replace(/ \(.*\)/, '')).join(', ')}) cannot be chosen here.</p>}
      {p.accepts_key && <Field label="API key" hint={<>{keyHint}{p.key_url && <> <a href={p.key_url} target="_blank" rel="noreferrer">Get a key</a></>}{keyState === 'dashboard' && isAdmin && <> · <button type="button" className="lg-link" onClick={() => onClearKey(p.id)}>remove saved key</button></>}</>}>
        <input type="password" value={keyValue} onChange={e => setKey(e.target.value)} disabled={!isAdmin || keyState === 'env'} placeholder={keyState ? '•••••••• (saved)' : p.key_prefix ? `${p.key_prefix}…` : ''} autoComplete="off" />
      </Field>}
      {p.base_url_editable && <Field label="Base URL" hint={p.id === 'ollama' ? 'Where Ollama listens, ending in /v1. Inside Docker Compose use http://ollama:11434/v1; on the host, http://host.docker.internal:11434/v1.' : 'The OpenAI-compatible API address, usually ending in /v1.'}>
        <input value={t.base_url} onChange={e => setTier({ base_url: e.target.value })} disabled={!isAdmin} placeholder={p.default_base_url || 'https://host/v1'} />
      </Field>}
      <Field label="Model" hint={<>{p.default_model ? `Default ${p.default_model}. ` : 'Required for this provider. '}{savedSame && isAdmin ? <button type="button" className="lg-link" disabled={busy} onClick={onModels}>Load models</button> : 'Save, then use Load models'} to see the ones your key can use.</>}>
        <input value={t.model} onChange={e => setTier({ model: e.target.value })} disabled={!isAdmin} placeholder={p.default_model} list={`ai-models-${tier}`} />
        <datalist id={`ai-models-${tier}`}>{models.map(m => <option key={m} value={m} />)}</datalist>
      </Field>
      {needsConfirm && <label className="check ai-confirm"><input type="checkbox" disabled={!isAdmin} checked={'zdr_confirmed' in t ? !!(t as { zdr_confirmed?: boolean }).zdr_confirmed : confirmed} onChange={e => setTier({ zdr_confirmed: e.target.checked })} />
        <span>This {p.label} account has <b>zero data retention / no training on our data</b> (a paid or enterprise plan, or a signed agreement). SM-Watch cannot check this from the key.
          {confirmed && <span className="sm muted"> Confirmed by {saved.tiers.confidential.zdr_confirmed_by} {timeAgo(saved.tiers.confidential.zdr_confirmed_at!)}.</span>}</span></label>}
      {savedSame && saved.tiers[tier].problem && saved.tiers[tier].enabled && <p className="sm warn" style={{ margin: '6px 0' }}>{saved.tiers[tier].problem}</p>}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        {isAdmin && <button className="btn sm" disabled={busy || !savedSame || !saved.tiers[tier].ready} title={!savedSame ? 'Save first' : undefined} onClick={onTest}>Test connection</button>}
        <span className="muted sm">This month: {saved.tiers[tier].usage.requests} requests · {saved.tiers[tier].usage.input_tokens.toLocaleString()} in / {saved.tiers[tier].usage.output_tokens.toLocaleString()} out tokens</span>
      </div>
    </section>
  );
}

const FEATURE_HINT: Record<Feature, string> = {
  incidents: 'sends the incident, the monitor\'s recent checks and metrics, other incidents and recent configuration changes',
  logs: 'sends the log lines shown (secrets masked): "Analyze with AI" and "Explain this line"',
  assistant: 'sends the question and the data it looks up: monitors, uptime, incidents, metrics, alerts, SLOs, and security findings (Confidential tier only)',
};

export function AiSettingsView() {
  const { isAdmin, toast, confirm } = useApp();
  const { value, reload } = usePoll(() => api<AiSettings>('/ai/settings'), [], 0);
  const [form, setForm] = useState<AiSettings | null>(null);
  const [keys, setKeys] = useState<Record<Tier, string>>({ dev: '', confidential: '' });
  const [models, setModels] = useState<Record<Tier, string[]>>({ dev: [], confidential: [] });
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (value) setForm(value); }, [value]);
  if (!form || !value) return <p className="muted">Loading…</p>;
  const set = (patch: Partial<AiSettings>) => setForm({ ...form, ...patch });
  const setTier = (tier: Tier) => (patch: Record<string, unknown>) => {
    if ('provider' in patch) { setKeys({ ...keys, [tier]: '' }); setModels({ ...models, [tier]: [] }); }
    setForm({ ...form, tiers: { ...form.tiers, [tier]: { ...form.tiers[tier], ...patch } } });
  };
  const setFeature = (f: Feature, tier: AiFeature['tier']) => setForm({ ...form, features: { ...form.features, [f]: { ...form.features[f], tier } } });
  const toShared = (Object.keys(form.features) as Feature[]).filter(f => form.features[f].tier === 'dev' && value.features[f].tier !== 'dev');
  const securityToShared = form.security_on_dev && !value.security_on_dev;

  async function save(extra: Record<string, unknown> = {}) {
    if (!form || !value) return;
    let acknowledge = false;
    if (toShared.length || securityToShared) {
      const what = [...toShared.map(f => form.features[f].label), ...(securityToShared ? ['security findings for the assistant'] : [])].join(', ');
      if (!(await confirm(`Send production data to the Development tier?\n\n${what} will use ${providerOf(form, 'dev')?.label}. Data sent through this tier may be logged, retained, or used by the provider for model training.\n\nYour name and the time are recorded in the audit log.`))) return;
      acknowledge = true;
    }
    setBusy(true);
    try {
      const tier = (t: Tier) => {
        const x = form.tiers[t] as AiSettings['tiers'][Tier] & { zdr_confirmed?: boolean };
        return { enabled: x.enabled, provider: x.provider, model: x.model, base_url: x.base_url, ...(t === 'confidential' && 'zdr_confirmed' in x ? { zdr_confirmed: x.zdr_confirmed } : {}) };
      };
      const newKeys = Object.fromEntries((['dev', 'confidential'] as Tier[]).filter(t => keys[t].trim()).map(t => [form.tiers[t].provider, keys[t].trim()]));
      const { auto_explain, post_explanations, allow_logs, anomaly_alerts, auto_per_hour, security_on_dev } = form;
      await put('/ai/settings', { tiers: { dev: tier('dev'), confidential: tier('confidential') }, features: Object.fromEntries((Object.keys(form.features) as Feature[]).map(f => [f, form.features[f].tier])),
        acknowledge_shared: acknowledge, auto_explain, post_explanations, allow_logs, anomaly_alerts, auto_per_hour, security_on_dev, keys: newKeys, ...extra });
      setKeys({ dev: '', confidential: '' }); toast('AI settings saved'); await reload();
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  async function test(tier: Tier) {
    setBusy(true);
    try { const r = await post<{ model: string }>(`/ai/test?tier=${tier}`); toast(`Connected: ${r.model} answered`); await reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  async function loadModels(tier: Tier) {
    setBusy(true);
    try { const r = await api<{ models: string[] }>(`/ai/models?tier=${tier}`); setModels({ ...models, [tier]: r.models }); toast(`${r.models.length} models available: pick one in the Model field`); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  const box = (k: keyof AiSettings, label: string, hint: string) => <label className="check"><input type="checkbox" disabled={!isAdmin} checked={Boolean(form[k])} onChange={e => set({ [k]: e.target.checked } as Partial<AiSettings>)} /><span>{label}<span className="sm muted"> — {hint}</span></span></label>;
  const card = (tier: Tier) => <TierCard tier={tier} form={form} saved={value} isAdmin={isAdmin} keyValue={keys[tier]} setKey={v => setKeys({ ...keys, [tier]: v })} setTier={setTier(tier)}
    onTest={() => void test(tier)} onClearKey={provider => void save({ clear_keys: [provider] })} onModels={() => void loadModels(tier)} models={models[tier]} busy={busy} />;
  return <>
    <div className="topbar"><div><h1>AI settings</h1><p className="muted sm">Two tiers keep production data away from providers that may keep or learn from it. Every AI feature uses the Confidential tier unless you move it explicitly.</p></div></div>
    <div className="grid g2 ai-tiers">{card('confidential')}{card('dev')}</div>
    <section className="card form-card" style={{ marginTop: 16 }}>
      <div className="card-head"><h2>Which tier each feature uses</h2></div>
      <table className="tbl"><thead><tr><th>Feature</th><th>Tier</th><th>Status</th></tr></thead><tbody>
        {(Object.keys(form.features) as Feature[]).map(f => <tr key={f}><td><b>{form.features[f].label}</b><div className="sm muted">{FEATURE_HINT[f]}</div></td>
          <td><select value={form.features[f].tier} disabled={!isAdmin} onChange={e => setFeature(f, e.target.value as AiFeature['tier'])}>
            <option value="confidential">Confidential (recommended)</option><option value="dev">Development · shared data</option><option value="off">Off</option></select></td>
          <td className="sm">{value.features[f].tier === form.features[f].tier ? (value.features[f].ready ? <span className="good">ready{value.features[f].tier === 'dev' && <> <SharedBadge tier="dev" /></>}</span> : <span className="warn">{value.features[f].problem}</span>) : <span className="muted">save to apply</span>}</td></tr>)}
      </tbody></table>
      {toShared.length > 0 && <div className="ai-warn" role="alert"><Icon name="alert" size={15} /><span>{toShared.map(f => form.features[f].label).join(', ')} will send production data to the Development tier, where it may be logged, retained or used for training. You will be asked to confirm when saving.</span></div>}
      <label className="check"><input type="checkbox" disabled={!isAdmin} checked={form.security_on_dev} onChange={e => set({ security_on_dev: e.target.checked })} />
        <span>Let the assistant read security findings when it runs on the Development tier<span className="sm muted"> — off by default: attackers, open ports and unpatched servers stay on the Confidential tier</span></span></label>
      {value.shared_ack && <p className="sm muted">Shared-data processing last accepted by {value.shared_ack.by} {timeAgo(value.shared_ack.at)} for: {value.shared_ack.what.join(', ')}.</p>}
    </section>
    <section className="card form-card" style={{ marginTop: 16 }}>
      <div className="card-head"><h2>Behaviour</h2></div>
      {box('auto_explain', 'Explain new incidents automatically', 'about 2 minutes after an incident opens, on the incidents tier')}
      <Field label="Automatic explanations per hour (limit)"><input type="number" min={1} max={60} value={form.auto_per_hour} onChange={e => set({ auto_per_hour: Number(e.target.value) })} disabled={!isAdmin} /></Field>
      {box('post_explanations', 'Post automatic explanations to alert channels', 'as a follow-up message')}
      {box('allow_logs', 'Allow "Analyze with AI" in the log viewer', 'operators send the lines shown, with secrets masked')}
      {box('anomaly_alerts', 'Send alerts for anomalies', 'no AI involved; uses the normal alert channels')}
      <p className="sm">This month ({form.month}): <b>{form.usage.requests}</b> requests · {form.usage.input_tokens.toLocaleString()} input tokens · {form.usage.output_tokens.toLocaleString()} output tokens</p>
      {isAdmin && <button className="btn primary" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</button>}
    </section>
  </>;
}
