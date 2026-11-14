'use client';

import { useEffect, useState } from 'react';
import { AreaChart } from '../components/charts';
import { useControlPlaneUrl } from '../components/join';
import { CodeBox, Empty, Icon } from '../components/ui';
import { api } from '../lib/api';
import { usePoll } from '../lib/app';
import type { Point } from '../lib/types';

type Range = '1h' | '6h' | '24h' | '7d' | '30d';
type Pct = { p50: number | null; p95: number | null; p99: number | null };
type TrafficSummary = Pct & { requests: number; rps: number | null; avg: number | null; max: number | null; upstream_avg: number | null; errors_5xx: number; errors_4xx: number; error_rate_5xx: number | null };
type TrafficServer = TrafficSummary & { server_id: number; name: string; series: Point[] };
type Traffic = { range: Range; servers: TrafficServer[]; total: TrafficSummary | null };
type CheckItem = Pct & { kind: 'service' | 'server'; id: number; name: string; checks: number; avg: number | null; max: number | null };
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

function PctTiles({ s }: { s: Pct & { avg?: number | null; max?: number | null } }) {
  return (
    <div className="pct-tiles">
      {(['p50', 'p95', 'p99'] as const).map(k => (
        <div key={k} className={`pct-tile ${k}`}><span className="pct-label">{k === 'p50' ? 'p50 · median' : k}</span><b>{dur(s[k])}</b>
          <small>{k === 'p50' ? 'half of requests are faster' : k === 'p95' ? '1 in 20 is slower' : '1 in 100 is slower'}</small></div>))}
      <div className="pct-tile"><span className="pct-label">Slowest</span><b>{dur(s.max)}</b><small>average {dur(s.avg)}</small></div>
    </div>
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
function RealTraffic({ range }: { range: Range }) {
  const { value, error } = usePoll(() => api<Traffic>(`/performance/traffic?range=${range}`), [range], 30000);
  if (error && !value) return <div className="err">{error}</div>;
  if (!value) return <p className="muted">Loading…</p>;
  if (value.servers.length === 0) return <Setup />;
  const t = value.total!;
  return (
    <div className="grid">
      {value.servers.length > 1 && <section className="card">
        <div className="card-head"><h2>All traffic</h2><span className="grow" /><span className="sm muted">{num(t.requests)} requests · {value.servers.length} server{value.servers.length === 1 ? '' : 's'}</span></div>
        <PctTiles s={t} />
        <div className="chips" style={{ marginTop: 14 }}>
          <span className="chip">{t.rps != null ? `${t.rps} requests/s` : '–'}</span>
          <span className={`chip ${(t.error_rate_5xx ?? 0) >= 1 ? 'warn' : ''}`}>{t.error_rate_5xx != null ? `${t.error_rate_5xx}% server errors (5xx)` : '–'}</span>
          <span className="chip">{num(t.errors_4xx)} client errors (4xx)</span>
        </div>
      </section>}
      {value.servers.map(s => <ServerTraffic key={s.server_id} s={s} range={range} />)}
    </div>
  );
}

function ServerTraffic({ s, range }: { s: TrafficServer; range: Range }) {
  const appShare = s.avg && s.upstream_avg != null ? Math.min(100, Math.round((s.upstream_avg / s.avg) * 100)) : null;
  return (
    <section className="card">
      <div className="card-head"><Icon name="server" size={16} /><h2>{s.name}</h2><span className="grow" /><Legend /></div>
      <PctTiles s={s} />
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
        SM-Watch can show how long real requests take, measured at your load balancer from the moment each request reaches it. The agent on that server summarises its nginx access log and sends only percentiles: no URLs, addresses or user agents.
      </Empty>
      <div className="setup">
        <div className="setup-step"><span className="step-n">1</span><div><b>Add the timing fields to the nginx log format</b>
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
  const { value, error } = usePoll(() => api<{ items: CheckItem[] }>(`/performance/checks?range=${range}`), [range], 30000);
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
        <div className="card-head"><h2>Services &amp; hosts, slowest first</h2><span className="grow" /><span className="sm muted">probes from the SM-Watch control plane</span></div>
        <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th className="num">p50</th><th className="num">p95</th><th className="num">p99</th><th className="num hide-sm">Slowest</th><th className="num hide-sm">Checks</th></tr></thead><tbody>
          {items.map(i => (
            <tr key={`${i.kind}/${i.id}`} className={`link ${sel === `${i.kind}/${i.id}` || (!sel && i === items[0]) ? 'sel' : ''}`} onClick={() => setSel(`${i.kind}/${i.id}`)}>
              <td><div className="name">{i.name}<small>{i.kind === 'service' ? 'HTTP service' : 'Host (ping)'}</small></div></td>
              <td className="num">{dur(i.p50)}</td><td className="num"><b>{dur(i.p95)}</b></td><td className="num">{dur(i.p99)}</td><td className="num hide-sm">{dur(i.max)}</td><td className="num hide-sm">{num(i.checks)}</td></tr>))}
        </tbody></table></div>
      </section>
      {chosen && (
        <section className="card">
          <div className="card-head"><h2>{chosen.name}</h2><span className="grow" /><Legend /></div>
          <PctTiles s={series.value ?? chosen} />
          <div style={{ marginTop: 14 }}><AreaChart points={series.value?.points ?? []} height={200} axisFormat={dur} series={PCT_SERIES} showDate={range !== '1h' && range !== '6h'} /></div>
        </section>)}
    </div>
  );
}
