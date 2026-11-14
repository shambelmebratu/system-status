'use client';

import { FormEvent, useEffect, useState } from 'react';
import { AreaChart } from '../components/charts';
import { useControlPlaneUrl } from '../components/join';
import { CodeBox, Empty, Field, Icon, Modal } from '../components/ui';
import { api, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';
import type { Point } from '../lib/types';

type Range = '1h' | '6h' | '24h' | '7d' | '30d';
type Pct = { p50: number | null; p95: number | null; p99: number | null };
type TrafficSummary = Pct & { requests: number; rps: number | null; avg: number | null; max: number | null; upstream_avg: number | null; errors_5xx: number; errors_4xx: number; error_rate_5xx: number | null };
type Target = { percentile: 'p50' | 'p95' | 'p99'; threshold_ms: number; window_minutes: number; value: number | null; samples: number; breaching: boolean };
type TrafficServer = TrafficSummary & { server_id: number; name: string; series: Point[]; last_data_at: string; target: Target | null };
type Traffic = { range: Range; servers: TrafficServer[]; total: TrafficSummary | null };
type CheckItem = Pct & { kind: 'service' | 'server'; id: number; name: string; checks: number; avg: number | null; max: number | null; target: Target | null };
type CheckSeries = Pct & { checks: number; avg: number | null; max: number | null; points: Point[] };

/** 1234 -> "1.23 s", 87.4 -> "87 ms" */
const dur = (v: number | null | undefined) => (v == null ? '–' : v === 0 ? '0' : v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 1 : 2)} s` : v >= 100 ? `${Math.round(v)} ms` : `${v.toFixed(v >= 10 ? 0 : 1)} ms`);
const num = (v: number | null | undefined) => (v == null ? '–' : v.toLocaleString());
const COLORS = { p50: 'var(--c4)', p95: 'var(--c3)', p99: 'var(--c5)' };
const PCT_SERIES = [{ key: 'p50', label: 'p50 (median)', color: COLORS.p50, format: dur }, { key: 'p95', label: 'p95', color: COLORS.p95, format: dur }, { key: 'p99', label: 'p99', color: COLORS.p99, format: dur }];
const RANGES: Range[] = ['1h', '6h', '24h', '7d', '30d'];

function Legend() {
  return <div className="legend">{PCT_SERIES.map(s => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}</div>;
}

const P95_MIN = 20, P99_MIN = 100;   // fewer samples than this and the percentile is little more than the slowest one

/** "Based on 1,234 requests", and a warning when there are too few for p95 / p99 to mean much. */
function Basis({ samples, noun, since }: { samples: number; noun: string; since?: string }) {
  const weak = samples < P95_MIN ? `p95 and p99 are not reliable yet (need ${P95_MIN}+ ${noun})` : samples < P99_MIN ? `p99 is not reliable yet (needs ${P99_MIN}+ ${noun})` : '';
  return (
    <div className="basis"><span>Based on <b>{num(samples)}</b> {noun}{since ? ` · latest ${timeAgo(since)}` : ''}</span>{weak && <span className="basis-warn" title="With very few samples, p95 and p99 are almost the same as the slowest request"><Icon name="alert" size={12} /> {weak}</span>}</div>
  );
}

function PctTiles({ s, samples }: { s: Pct & { avg?: number | null; max?: number | null }; samples?: number }) {
  return (
    <div className="pct-tiles">
      {(['p50', 'p95', 'p99'] as const).map(k => {
        const weak = samples != null && samples < (k === 'p99' ? P99_MIN : k === 'p95' ? P95_MIN : 1);
        return (
          <div key={k} className={`pct-tile ${k} ${weak ? 'weak' : ''}`}><span className="pct-label">{k === 'p50' ? 'p50 · median' : k}</span><b>{weak ? '≈ ' : ''}{dur(s[k])}</b>
            <small>{k === 'p50' ? 'half of requests are faster' : k === 'p95' ? '1 in 20 is slower' : '1 in 100 is slower'}</small></div>);
      })}
      <div className="pct-tile"><span className="pct-label">Slowest</span><b>{dur(s.max)}</b><small>average {dur(s.avg)}</small></div>
    </div>
  );
}

/** The response-time target of a monitor: its state, and (for operators) a way to set or change it. */
function TargetChip({ target, kind, id, name, onSaved }: { target: Target | null; kind: 'service' | 'server'; id: number; name: string; onSaved: () => void }) {
  const { canOperate } = useApp();
  const [open, setOpen] = useState(false);
  const fmt = (t: Target) => `${t.percentile} ≤ ${dur(t.threshold_ms)}`;
  let body;
  if (!target) body = <span className="muted">No target</span>;
  else if (target.value == null) body = <><span className="target wait">{fmt(target)}</span><span className="muted"> waiting for data ({num(target.samples)} in the last {target.window_minutes} min)</span></>;
  else body = <><span className={`target ${target.breaching ? 'bad' : 'ok'}`}>{fmt(target)}</span><span className={target.breaching ? 'bad' : 'good'}> {target.breaching ? `too slow: ${target.percentile} is ${dur(target.value)}` : `met: ${target.percentile} is ${dur(target.value)}`}</span><span className="muted"> · last {target.window_minutes} min</span></>;
  return (
    <div className="target-line">{body}{canOperate && <button className="btn sm ghost" onClick={e => { e.stopPropagation(); setOpen(true); }}>{target ? 'Edit' : 'Set a target'}</button>}
      {open && <TargetEditor target={target} kind={kind} id={id} name={name} onClose={() => setOpen(false)} onSaved={() => { setOpen(false); onSaved(); }} />}</div>
  );
}

function TargetEditor({ target, kind, id, name, onClose, onSaved }: { target: Target | null; kind: 'service' | 'server'; id: number; name: string; onClose: () => void; onSaved: () => void }) {
  const { toast } = useApp();
  const [percentile, setPercentile] = useState(target?.percentile ?? 'p95');
  const [threshold, setThreshold] = useState(String(target?.threshold_ms ?? 500));
  const [windowMin, setWindowMin] = useState(String(target?.window_minutes ?? 10));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function save(e: FormEvent, remove = false) {
    e.preventDefault(); setBusy(true); setError('');
    try { await put(`/performance/targets/${kind}/${id}`, remove ? { threshold_ms: null } : { percentile, threshold_ms: Number(threshold), window_minutes: Number(windowMin) }); toast(remove ? 'Target removed' : 'Target saved'); onSaved(); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  const noun = kind === 'server' ? 'requests through the load balancer' : 'checks';
  return (
    <Modal title={`Response-time target · ${name}`} onClose={onClose}>
      <form onSubmit={save} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <p className="muted sm">Raise an alert (&ldquo;Over a limit&rdquo;, with an incident) when the chosen percentile of the {noun} over the window is slower than the target, and a recovery message when it is back under. Where the alert goes is set in this monitor&apos;s Alerts section.</p>
        <div className="form-grid">
          <Field label="Percentile" hint={percentile === 'p50' ? 'The typical request' : percentile === 'p95' ? 'Ignores the slowest 5%' : 'Ignores the slowest 1%; needs lots of traffic'}><select value={percentile} onChange={e => setPercentile(e.target.value as Target['percentile'])}><option value="p50">p50 (median)</option><option value="p95">p95</option><option value="p99">p99</option></select></Field>
          <Field label="Must be faster than (ms)"><input type="number" min={1} max={600000} value={threshold} onChange={e => setThreshold(e.target.value)} required /></Field>
          <Field label="Over the last (minutes)" hint="Longer = fewer false alarms, slower to notice"><input type="number" min={1} max={1440} value={windowMin} onChange={e => setWindowMin(e.target.value)} required /></Field>
        </div>
        <p className="sm muted">Not judged until there are enough samples in the window (a handful of requests says nothing). Example: &ldquo;{percentile} faster than {threshold || '…'} ms over {windowMin || '…'} min&rdquo;.</p>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          {target && <button type="button" className="btn danger" disabled={busy} onClick={e => void save(e as unknown as FormEvent, true)}>Remove target</button>}
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>Save target</button>
        </div>
      </form>
    </Modal>
  );
}

export function Performance() {
  const [range, setRange] = useState<Range>('24h');
  const [tab, setTab] = useState<'traffic' | 'checks'>('traffic');
  return (
    <>
      <div className="topbar">
        <div><h1>Performance</h1><p className="muted sm">Response times as percentiles: p50 is the typical request, p95 and p99 are the slow tail your unluckiest users feel.</p></div>
        <span className="grow" />
        <div className="seg">{RANGES.map(r => <button key={r} className={range === r ? 'on' : ''} onClick={() => setRange(r)}>{r}</button>)}</div>
      </div>
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'traffic'} className={tab === 'traffic' ? 'on' : ''} onClick={() => setTab('traffic')}>Real traffic · load balancer</button>
        <button role="tab" aria-selected={tab === 'checks'} className={tab === 'checks' ? 'on' : ''} onClick={() => setTab('checks')}>Synthetic checks</button>
      </div>
      {tab === 'traffic' ? <RealTraffic range={range} /> : <SyntheticChecks range={range} />}
    </>
  );
}

/* ---------------------------------------------------------------- real traffic */
type TrafficStatus = { state: 'off' | 'no_file' | 'unreadable' | 'waiting' | 'no_timing' | 'ok'; path?: string; lines?: number; parsed?: number; detected?: { path: string; timing: boolean }[] };

/** What each agent says about its access log: measuring, or exactly what is missing. */
function DataSources() {
  const { data } = useApp();
  const [base] = useControlPlaneUrl();
  const rows = (data?.servers ?? []).filter(s => s.monitor_mode === 'push' && s.last_metrics && (s.last_metrics as { traffic_status?: TrafficStatus }).traffic_status)
    .map(s => ({ s, st: (s.last_metrics as { traffic_status: TrafficStatus }).traffic_status }))
    .filter(({ st }) => st.state !== 'off' || (st.detected?.length ?? 0) > 0);
  if (rows.length === 0) return null;
  const explain = (st: TrafficStatus): { tone: 'good' | 'warn' | 'bad' | 'muted'; label: string; text: string; fix?: string } => {
    const found = st.detected?.[0];
    switch (st.state) {
      case 'ok': return { tone: 'good', label: 'Measuring', text: `Reading ${st.path}: ${num(st.parsed)} requests with a response time in the last report.` };
      case 'waiting': return { tone: 'muted', label: 'Waiting for requests', text: `Reading ${st.path}, but no new requests were logged since the last report.` };
      case 'no_timing': return { tone: 'warn', label: 'No response time in the log', text: `${num(st.lines)} requests were logged in ${st.path}, but none has a response time. Add rt=$request_time urt=$upstream_response_time to the nginx log_format (or use a JSON log with request_time) and reload nginx.` };
      case 'no_file': return { tone: 'bad', label: 'Log not found', text: `The agent is told to read ${st.path}, but no such file exists on that server. Check the path.` };
      case 'unreadable': return { tone: 'bad', label: 'Cannot read the log', text: `${st.path} exists but the agent is not allowed to read it. Add the agent user to the group that owns it (usually "adm"), or re-run the install with a readable log.` };
      default: return found?.timing
        ? { tone: 'warn', label: 'Ready to switch on', text: `Found ${found.path}, and its lines already carry a response time. Tell the agent to read it:`, fix: `curl -fsSL ${base}/api/agent/install.sh | sudo SMWATCH_ACCESS_LOG=${found.path} bash -s -- update` }
        : { tone: 'warn', label: 'Log found, no response time', text: `Found ${found?.path}, but its lines carry no response time. Add rt=$request_time urt=$upstream_response_time to the nginx log_format, reload nginx, then tell the agent to read it (step 2 below).` };
    }
  };
  return (
    <section className="card">
      <div className="card-head"><h2>Data sources</h2><span className="grow" /><span className="sm muted">what each agent reports about its access log</span></div>
      <div className="sources">{rows.map(({ s, st }) => { const e = explain(st); return (
        <div key={s.id} className="source"><div className="source-head"><b>{s.name}</b><span className={`source-state ${e.tone}`}>{e.label}</span></div>
          <div className="sm muted">{e.text}</div>{e.fix && <CodeBox value={e.fix} />}</div>); })}</div>
    </section>
  );
}

function RealTraffic({ range }: { range: Range }) {
  const { value, error, reload } = usePoll(() => api<Traffic>(`/performance/traffic?range=${range}`), [range], 30000);
  if (error && !value) return <div className="err">{error}</div>;
  if (!value) return <p className="muted">Loading…</p>;
  if (value.servers.length === 0) return <div className="grid"><DataSources /><Setup /></div>;
  const t = value.total!;
  return (
    <div className="grid">
      <DataSources />
      {value.servers.length > 1 && <section className="card">
        <div className="card-head"><h2>All traffic</h2><span className="grow" /><span className="sm muted">{num(t.requests)} requests · {value.servers.length} server{value.servers.length === 1 ? '' : 's'}</span></div>
        <PctTiles s={t} samples={t.requests} />
        <Basis samples={t.requests} noun="requests" />
        <div className="chips" style={{ marginTop: 14 }}>
          <span className="chip">{t.rps != null ? `${t.rps} requests/s` : '–'}</span>
          <span className={`chip ${(t.error_rate_5xx ?? 0) >= 1 ? 'warn' : ''}`}>{t.error_rate_5xx != null ? `${t.error_rate_5xx}% server errors (5xx)` : '–'}</span>
          <span className="chip">{num(t.errors_4xx)} client errors (4xx)</span>
        </div>
      </section>}
      {value.servers.map(s => <ServerTraffic key={s.server_id} s={s} range={range} onChanged={() => void reload()} />)}
    </div>
  );
}

function ServerTraffic({ s, range, onChanged }: { s: TrafficServer; range: Range; onChanged: () => void }) {
  const appShare = s.avg && s.upstream_avg != null ? Math.min(100, Math.round((s.upstream_avg / s.avg) * 100)) : null;
  return (
    <section className="card">
      <div className="card-head"><Icon name="server" size={16} /><h2>{s.name}</h2><span className="grow" /><Legend /></div>
      <PctTiles s={s} samples={s.requests} />
      <Basis samples={s.requests} noun="requests" since={s.last_data_at} />
      <TargetChip target={s.target} kind="server" id={s.server_id} name={s.name} onSaved={onChanged} />
      <div className="chips" style={{ marginTop: 14 }}>
        <span className="chip">{num(s.requests)} requests</span><span className="chip">{s.rps != null ? `${s.rps} requests/s` : '–'}</span>
        <span className={`chip ${(s.error_rate_5xx ?? 0) >= 1 ? 'warn' : ''}`}>{s.error_rate_5xx != null ? `${s.error_rate_5xx}% server errors (5xx)` : '–'}</span><span className="chip">{num(s.errors_4xx)} client errors (4xx)</span>
      </div>
      <div style={{ marginTop: 14 }}><AreaChart points={s.series} height={190} axisFormat={dur} series={PCT_SERIES} showDate={range !== '1h' && range !== '6h'} /></div>
      <div className="grid g2" style={{ marginTop: 14 }}>
        <div><div className="sm muted" style={{ marginBottom: 4 }}>Requests per minute</div>
          <AreaChart points={s.series} height={110} series={[{ key: 'rpm', label: 'Requests/min', color: 'var(--c1)' }]} /></div>
        <div><div className="sm muted" style={{ marginBottom: 4 }}>Server errors (5xx, % of requests)</div>
          <AreaChart points={s.series} height={110} unit="%" series={[{ key: 'errors', label: '5xx', color: 'var(--bad)', format: v => `${v}%` }]} /></div>
      </div>
      <div className="split">
        <div className="split-head"><b>Where the time goes</b><span className="sm muted">average {dur(s.avg)} per request</span></div>
        {appShare != null ? <>
          <div className="stack"><i style={{ width: `${appShare}%`, background: 'var(--c2)' }} title="Application (upstream)" /><i style={{ width: `${100 - appShare}%`, background: 'var(--c1)' }} title="Load balancer, network and client" /></div>
          <div className="stack-legend"><span><i style={{ background: 'var(--c2)' }} />Your application (upstream) <b>{dur(s.upstream_avg)}</b></span><span><i style={{ background: 'var(--c1)' }} />Load balancer, network &amp; client <b>{dur(Math.max(0, (s.avg ?? 0) - (s.upstream_avg ?? 0)))}</b></span></div>
        </> : <p className="sm muted">Add <code>urt=$upstream_response_time</code> to the nginx log format to see how much of this is your application.</p>}
      </div>
    </section>
  );
}

function Setup() {
  const [base] = useControlPlaneUrl();
  return (
    <div className="card">
      <Empty title="No real-traffic data yet">
        SM-Watch can show how long real requests take, measured at your load balancer from the moment each request reaches it. The agent on that server summarises its access log (nginx, Caddy, Traefik or HAProxy) and sends only percentiles: no URLs, addresses or user agents. Once an agent is updated to 2.11 it also tells you here whether it found a log and what is missing.
      </Empty>
      <div className="setup">
        <div className="setup-step"><span className="step-n">1</span><div><b>Make the load balancer log the response time</b> <span className="muted sm">(nginx shown; Caddy and Traefik JSON logs and HAProxy&apos;s http log already include it)</span>
          <CodeBox value={`log_format smwatch '$remote_addr - $remote_user [$time_local] "$request_method $request_uri $server_protocol" '\n                   '$status $body_bytes_sent "$http_user_agent" rt=$request_time urt=$upstream_response_time';\naccess_log /var/log/nginx/access.log smwatch;`} />
          <span className="sm muted"><code>rt</code> starts when the request reaches nginx, so it covers everything after that. Then reload nginx.</span></div></div>
        <div className="setup-step"><span className="step-n">2</span><div><b>Tell the agent where the log is</b>
          <CodeBox value={`curl -fsSL ${base}/api/agent/install.sh | sudo SMWATCH_ACCESS_LOG=/var/log/nginx/access.log bash -s -- update`} />
          <span className="sm muted">Docker agent: add <code>-e AGENT_ACCESS_LOG=/var/log/nginx/access.log</code>. Agent bundled with SM-Watch: set <code>HOST_ACCESS_LOG</code> in <code>.env</code> and restart <code>host-agent</code>. Needs agent 2.10 or newer.</span></div></div>
        <div className="setup-step"><span className="step-n">3</span><div><b>Wait a minute</b><span className="sm muted" style={{ display: 'block' }}>Only requests logged after the agent starts are counted. The first data appears with its next report.</span></div></div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- synthetic checks */
function SyntheticChecks({ range }: { range: Range }) {
  const { value, error, reload } = usePoll(() => api<{ items: CheckItem[] }>(`/performance/checks?range=${range}`), [range], 30000);
  const [sel, setSel] = useState<string | null>(null);
  const items = value?.items ?? [];
  useEffect(() => { if (!sel && items.length) setSel(`${items[0].kind}/${items[0].id}`); }, [items, sel]);
  const chosen = items.find(i => `${i.kind}/${i.id}` === sel) ?? items[0];
  const series = usePoll(() => (chosen ? api<CheckSeries>(`/performance/checks/${chosen.kind}/${chosen.id}?range=${range}`) : Promise.resolve(null)), [chosen?.kind, chosen?.id, range], 30000);
  if (error && !value) return <div className="err">{error}</div>;
  if (!value) return <p className="muted">Loading…</p>;
  if (items.length === 0) return <div className="card"><Empty title="No checks in this range">Add a service or a ping-monitored server. Response times appear after its first checks.</Empty></div>;
  return (
    <div className="grid">
      <section className="card">
        <div className="card-head"><h2>Services &amp; hosts, slowest first</h2><span className="grow" /><span className="sm muted">probes SM-Watch runs itself, every check interval</span></div>
        <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th className="num">p50</th><th className="num">p95</th><th className="num">p99</th><th className="num hide-sm">Slowest</th><th className="num">Samples</th><th>Target</th></tr></thead><tbody>
          {items.map(i => (
            <tr key={`${i.kind}/${i.id}`} className={`link ${sel === `${i.kind}/${i.id}` || (!sel && i === items[0]) ? 'sel' : ''}`} onClick={() => setSel(`${i.kind}/${i.id}`)}>
              <td><div className="name">{i.name}<small>{i.kind === 'service' ? 'HTTP service' : 'Host (ping)'}</small></div></td>
              <td className="num">{dur(i.p50)}</td><td className="num"><b>{dur(i.p95)}</b></td><td className="num">{dur(i.p99)}</td><td className="num hide-sm">{dur(i.max)}</td><td className={`num ${i.checks < P99_MIN ? 'warn' : ''}`} title={i.checks < P99_MIN ? `Few samples: p99 is not reliable yet (needs ${P99_MIN}+)` : ''}>{num(i.checks)}</td>
              <td className="sm" onClick={e => e.stopPropagation()}>{i.kind === 'service' ? <TargetChip target={i.target} kind="service" id={i.id} name={i.name} onSaved={() => void reload()} /> : <span className="muted">–</span>}</td></tr>))}
        </tbody></table></div>
      </section>
      {chosen && (
        <section className="card">
          <div className="card-head"><h2>{chosen.name}</h2><span className="grow" /><Legend /></div>
          <PctTiles s={series.value ?? chosen} samples={series.value?.checks ?? chosen.checks} />
          <Basis samples={series.value?.checks ?? chosen.checks} noun="checks" />
          <div style={{ marginTop: 14 }}><AreaChart points={series.value?.points ?? []} height={200} axisFormat={dur} series={PCT_SERIES} showDate={range !== '1h' && range !== '6h'} /></div>
        </section>)}
    </div>
  );
}
