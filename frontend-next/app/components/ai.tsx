'use client';

import { Fragment, ReactNode, useState } from 'react';
import { Icon } from './ui';
import { api, post } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

export type AiProvider = { id: string; label: string; default_model: string; needs_key: boolean; accepts_key: boolean; key_env: string | null; key_prefix: string | null;
  key_url: string | null; base_url_editable: boolean; default_base_url: string; tools: boolean; free: string; destination: string; key_saved: boolean; key_in_env: boolean;
  privacy: 'local' | 'zdr_possible' | 'shared'; privacy_text: string; policy: string; policy_url: string };
export type Tier = 'dev' | 'confidential';
export type Feature = 'incidents' | 'logs' | 'assistant';
type Usage = { requests: number; input_tokens: number; output_tokens: number };
export type AiTier = { enabled: boolean; provider: string; model: string; base_url: string; key_source: 'env' | 'dashboard' | null; ready: boolean; problem: string | null; usage: Usage;
  zdr_confirmed_by?: string | null; zdr_confirmed_at?: string | null };
export type AiFeature = { label: string; tier: Tier | 'off'; ready: boolean; problem: string | null; destination: string | null };
export type AiSettings = { auto_explain: boolean; post_explanations: boolean; allow_logs: boolean; anomaly_alerts: boolean; auto_per_hour: number; security_on_dev: boolean;
  tiers: Record<Tier, AiTier>; features: Record<Feature, AiFeature>; shared_ack: { by: string; at: string; what: string[] } | null; ready: boolean;
  providers: AiProvider[]; usage: Usage; month: string };

export function providerOf(settings: AiSettings | null | undefined, tier: Tier): AiProvider | undefined {
  return settings?.providers.find(p => p.id === settings.tiers[tier].provider);
}

/** Shown next to anything produced on the Development tier: the provider may keep or learn from what was sent. */
export function SharedBadge({ tier }: { tier?: string }) {
  if (tier !== 'dev') return null;
  return <span className="ai-shared" title="Sent through the Development tier: the provider may log, retain or train on this data">shared data</span>;
}
export type IncidentAnalysis = { summary: string; impact: string; likely_causes: { cause: string; evidence: string; confidence: 'low' | 'medium' | 'high' }[]; next_checks: string[]; related: string[]; error?: string };
type LogAnalysis = { summary: string; health: 'healthy' | 'degraded' | 'failing'; groups: { title: string; severity: string; occurrences: number; example: string; meaning: string; fix: string }[];
  next_steps: string[]; model: string; tier?: string; lines_sent: number };

export function useAi() {
  return usePoll(() => api<AiSettings>('/ai/settings'), [], 120000).value;
}

/* ---------------------------------------------------------------- tiny, safe markdown (no HTML is ever injected) */
function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m: RegExpExecArray | null, i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(m[0].startsWith('**') ? <b key={i++}>{m[0].slice(2, -2)}</b> : <code key={i++}>{m[0].slice(1, -1)}</code>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Markdown({ text }: { text: string }) {
  const lines = text.replace(/\r/g, '').split('\n');
  const blocks: ReactNode[] = [];
  let i = 0, k = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (line.trim().startsWith('```')) {
      const code: string[] = []; i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) code.push(lines[i++]);
      i++; blocks.push(<pre key={k++} className="md-code">{code.join('\n')}</pre>); continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line)) {
      const rows: string[][] = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        const cells = lines[i].trim().slice(1, -1).split('|').map(c => c.trim());
        if (!cells.every(c => /^:?-{2,}:?$/.test(c))) rows.push(cells);
        i++;
      }
      blocks.push(<div key={k++} className="tbl-wrap"><table className="tbl md-table"><thead><tr>{rows[0].map((c, j) => <th key={j}>{inline(c)}</th>)}</tr></thead>
        <tbody>{rows.slice(1).map((r, n) => <tr key={n}>{r.map((c, j) => <td key={j}>{inline(c)}</td>)}</tr>)}</tbody></table></div>);
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*([-*]|\d+\.)\s+/, ''));
      const List = ordered ? 'ol' : 'ul';
      blocks.push(<List key={k++}>{items.map((t, n) => <li key={n}>{inline(t)}</li>)}</List>); continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) { blocks.push(<h4 key={k++} className="md-h">{inline(h[2])}</h4>); i++; continue; }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^\s*([-*]|\d+\.)\s+|^\s*\||^#{1,4}\s|^```/.test(lines[i])) para.push(lines[i++]);
    blocks.push(<p key={k++}>{para.map((p, n) => <Fragment key={n}>{n > 0 && <br />}{inline(p)}</Fragment>)}</p>);
  }
  return <div className="md">{blocks}</div>;
}

/* ---------------------------------------------------------------- incident explanation */
export function IncidentAi({ incidentId, analysis, model, generatedAt, onDone }: { incidentId: number; analysis: IncidentAnalysis | null; model: string | null; generatedAt: string | null; onDone: () => void }) {
  const settings = useAi();
  const { canOperate, toast } = useApp();
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  async function explain(e: React.MouseEvent) {
    e.stopPropagation(); setBusy(true);
    try { await post(`/incidents/${incidentId}/explain`); setOpen(true); onDone(); } catch (err) { toast((err as Error).message, true); } finally { setBusy(false); }
  }
  if (analysis && !analysis.error) return (
    <div className="ai-box" onClick={e => e.stopPropagation()}>
      <button type="button" className="ai-head" onClick={() => setOpen(!open)} aria-expanded={open}><span className="ai-badge"><Icon name="zap" size={12} />AI</span><span className="trunc">{analysis.summary}</span><span className="grow" /><span className="muted">{open ? '▾' : '▸'}</span></button>
      {open && <div className="ai-body">
        <p><b>Impact:</b> {analysis.impact}</p>
        <h4>Likely causes</h4>
        <ul className="ai-causes">{analysis.likely_causes.map((c, i) => <li key={i}><span className={`ai-conf ${c.confidence}`}>{c.confidence}</span><div><b>{c.cause}</b><div className="sm muted">{c.evidence}</div></div></li>)}</ul>
        <h4>Check next</h4><ol>{analysis.next_checks.map((c, i) => <li key={i}><Markdown text={c} /></li>)}</ol>
        {analysis.related.length > 0 && <><h4>Related</h4><ul>{analysis.related.map((r, i) => <li key={i}>{r}</li>)}</ul></>}
        <p className="sm muted">{model} · {generatedAt ? timeAgo(generatedAt) : ''} · AI can be wrong: check before acting.{canOperate && settings?.features.incidents.ready && <> <button className="lg-link" onClick={explain} disabled={busy}>{busy ? 'Thinking…' : 'Explain again'}</button></>}</p>
      </div>}
    </div>);
  if (!canOperate || !settings?.features.incidents.ready) return null;
  return <div className="ai-box" onClick={e => e.stopPropagation()}>
    <button type="button" className="btn sm" onClick={explain} disabled={busy}><Icon name="zap" size={13} />{busy ? 'Thinking… (up to a minute)' : 'Explain with AI'}</button>
    {analysis?.error && <span className="sm warn" style={{ marginLeft: 8 }}>Last attempt failed: {analysis.error}</span>}
  </div>;
}

/* ---------------------------------------------------------------- log analysis */
export function LogAiButton({ getText, source }: { getText: () => string; source: string }) {
  const settings = useAi();
  const { canOperate, toast } = useApp();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LogAnalysis | null>(null);
  if (!canOperate || !settings?.features.logs.ready || !settings.allow_logs) return null;
  async function run() {
    const text = getText();
    if (!text.trim()) { toast('There are no lines to analyse', true); return; }
    setBusy(true);
    try { setResult(await post<LogAnalysis>('/ai/logs', { text, source })); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  return <>
    <button type="button" className="btn sm" onClick={run} disabled={busy} title="Send the lines shown (secrets masked) to the AI for a summary"><Icon name="zap" size={13} />{busy ? 'Analysing…' : 'Analyze with AI'}</button>
    {result && <div className="drawer-overlay" onMouseDown={e => e.target === e.currentTarget && setResult(null)}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="AI log analysis">
        <div className="drawer-head"><div><div className="sm muted">AI log analysis · {source}</div><h2>{result.health === 'healthy' ? 'Looks healthy' : result.health === 'degraded' ? 'Degraded' : 'Failing'}</h2></div><span className="grow" /><button className="btn ghost sm" onClick={() => setResult(null)} aria-label="Close"><Icon name="x" /></button></div>
        <div className="drawer-body">
          <p>{result.summary}</p>
          {result.groups.map((g, i) => <div key={i} className={`ai-group ${g.severity}`}><div className="ai-group-head"><b>{g.title}</b><span className="tag">~{g.occurrences.toLocaleString()}×</span></div>
            <code className="ai-example">{g.example}</code><p className="sm">{g.meaning}</p>{g.fix && <p className="sm"><b>Fix:</b> {g.fix}</p>}</div>)}
          {result.next_steps.length > 0 && <><h3 className="drawer-h">Next steps</h3><ol>{result.next_steps.map((s, i) => <li key={i}><Markdown text={s} /></li>)}</ol></>}
          <p className="sm muted">{result.lines_sent.toLocaleString()} lines sent with secrets masked · {result.model} <SharedBadge tier={result.tier} /> · AI can be wrong.</p>
        </div>
      </aside>
    </div>}
  </>;
}

/* ---------------------------------------------------------------- one log line */
type LineExplanation = { summary: string; severity: 'error' | 'warning' | 'info'; meaning: string; likely_causes: string[]; fix: string[]; needs_attention: boolean; model: string; tier?: string; context_lines: number };

/** "Explain with AI" for the line open in the log inspector. The surrounding lines go along as context; secrets are masked on the server. */
export function LogLineAi({ line, before, after, source }: { line: string; before: string[]; after: string[]; source: string }) {
  const settings = useAi();
  const { canOperate } = useApp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<LineExplanation | null>(null);
  const [forLine, setForLine] = useState('');
  if (!canOperate || !settings?.features.logs.ready || !settings.allow_logs) return null;
  const shown = forLine === line ? result : null;          // moving to another line hides the old explanation
  async function run() {
    setBusy(true); setError('');
    try { setResult(await post<LineExplanation>('/ai/log-line', { line, before, after, source })); setForLine(line); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return <div className="ai-line">
    {!shown && <button type="button" className="btn sm" onClick={run} disabled={busy} title="Send this line and a few around it (secrets masked) to the AI">
      <Icon name="zap" size={13} />{busy ? 'Thinking…' : 'Explain this line with AI'}</button>}
    {error && <div className="err sm" style={{ marginTop: 8 }}>{error}</div>}
    {shown && <div className={`ai-group ${shown.severity}`}>
      <div className="ai-group-head"><b>{shown.summary}</b><span className="tag">{shown.needs_attention ? 'needs attention' : 'routine'}</span></div>
      <p className="sm">{shown.meaning}</p>
      {shown.likely_causes.length > 0 && <><h4 className="drawer-h">Likely causes</h4><ul className="sm">{shown.likely_causes.map((c, i) => <li key={i}><Markdown text={c} /></li>)}</ul></>}
      {shown.fix.length > 0 && <><h4 className="drawer-h">What to do</h4><ol className="sm">{shown.fix.map((f, i) => <li key={i}><Markdown text={f} /></li>)}</ol></>}
      <p className="sm muted">{shown.model} <SharedBadge tier={shown.tier} /> · {shown.context_lines} surrounding lines sent as context, secrets masked · AI can be wrong. <button type="button" className="lg-link" onClick={run} disabled={busy}>{busy ? 'Thinking…' : 'Ask again'}</button></p>
    </div>}
  </div>;
}

