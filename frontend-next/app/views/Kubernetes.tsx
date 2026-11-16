'use client';

import { FormEvent, ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { AreaChart, Sparkline } from '../components/charts';
import { ClusterAgentUpdate } from '../components/agentupdate';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { useActiveEnrollment, useControlPlaneUrl } from '../components/join';
import { LogViewer, TargetPicker, type LogFetch } from '../components/logviewer';
import { CodeBox, Empty, Field, Icon, Meter, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, useLimits, usePoll } from '../lib/app';
import { pct, timeAgo } from '../lib/format';
import type { Cluster, K8sLogPolicy, Point } from '../lib/types';

/* ---------------------------------------------------------------- querying the in-cluster agent */
type Answer<T> = { id: number; status: 'pending' | 'running' | 'done' | 'error'; error: string | null; truncated: boolean; data?: T; text?: string };

async function ask<T>(clusterId: number, query: Record<string, unknown>, cancelled: () => boolean): Promise<Answer<T>> {
  const { id } = await post<{ id: number }>(`/clusters/${clusterId}/query`, query);
  const deadline = Date.now() + 50_000;
  while (Date.now() < deadline) {
    if (cancelled()) throw new Error('cancelled');
    const result = await api<Answer<T>>(`/clusters/${clusterId}/query/${id}?wait=15`);
    if (result.status === 'done') return result;
    if (result.status === 'error') throw new Error(result.error || 'The agent could not answer');
  }
  throw new Error('Timed out waiting for the cluster agent');
}

/** The page-wide "live" clock: every tick re-asks the cluster. `touch` records when fresh data last arrived. */
type Live = { tick: number; ms: number; touch: () => void };
const LiveCtx = createContext<Live>({ tick: 0, ms: 0, touch: () => undefined });
/** What the page's pieces can ask the cluster detail to do: open a pod's side panel, show a namespace's pods. */
type Nav = { openPod: (ns: string, name: string) => void; open: (t: { resource: string; ns: string; name: string }) => void; goPods: (ns: string) => void };
const NavCtx = createContext<Nav>({ openPod: () => undefined, open: () => undefined, goPods: () => undefined });

/** Fetches a list from the cluster when mounted (and when `deps` change). With refreshMs > 0 it follows the page's live clock and
 *  refreshes in the background (the old rows stay on screen until the new ones arrive). Nothing is stored on the control plane. */
function useCluster<T>(clusterId: number, query: Record<string, unknown> | null, deps: unknown[], refreshMs = 0) {
  const live = useContext(LiveCtx);
  const [state, setState] = useState<{ data: Answer<T> | null; error: string; busy: boolean }>({ data: null, error: '', busy: false });
  const [tick, setTick] = useState(0);
  const followLive = refreshMs > 0 ? live.tick : 0;
  useEffect(() => {
    if (!query) return;
    let stop = false;
    setState(s => ({ ...s, busy: true }));
    ask<T>(clusterId, query, () => stop).then(data => { if (!stop) { setState({ data, error: '', busy: false }); live.touch(); } })
      .catch(e => !stop && (e as Error).message !== 'cancelled' && setState(s => ({ ...s, error: (e as Error).message, busy: false })));
    return () => { stop = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterId, tick, followLive, ...deps]);
  return { ...state, reload: () => setTick(n => n + 1) };
}

type Items<R> = { items: R[]; truncated: boolean };

/* ---------------------------------------------------------------- routing */
export function Kubernetes() {
  const lim = useLimits();
  const { route, go, canOperate, canManage } = useApp();
  const { value: clusters, reload } = usePoll(() => api<Cluster[]>('/clusters'), [], 10000);
  if (!clusters) return <p className="muted">Loading…</p>;
  if (route[1] && route[1] !== 'new') {
    const cluster = clusters.find(c => c.id === Number(route[1]));
    return cluster ? <ClusterDetail cluster={cluster} reload={reload} /> : <Empty title="Cluster not found" action={<button className="btn" onClick={() => go('kubernetes')}>Back to clusters</button>} />;
  }
  return (
    <>
      <div className="topbar"><h1>Kubernetes</h1><span className="grow" />{canManage && <button className="btn primary" onClick={() => go('kubernetes/new')}><Icon name="plus" size={15} />Add cluster</button>}</div>
      {clusters.length === 0 ? (
        <div className="card"><Empty title="No clusters yet" action={canManage ? <button className="btn primary" onClick={() => go('kubernetes/new')}>Connect your first cluster</button> : undefined}>
          Install a small read-only agent in a cluster to see nodes, pods, workloads, autoscalers and resource usage, and to read pod logs on demand.</Empty></div>
      ) : (
        <>
          <div className="kpis" style={{ marginBottom: 16 }}>
            <Kpi icon="k8s" label="Clusters" value={clusters.length} sub={`${clusters.filter(c => c.status === 'up').length} healthy`} tone={clusters.some(c => c.status !== 'up') ? 'warn' : 'good'} />
            <Kpi icon="server" label="Nodes" value={clusters.reduce((n, c) => n + (c.summary?.nodes_total ?? 0), 0)} sub={`${clusters.reduce((n, c) => n + (c.summary?.nodes_ready ?? 0), 0)} ready`} />
            <Kpi icon="overview" label="Pods" value={clusters.reduce((n, c) => n + (c.summary?.pods_total ?? 0), 0).toLocaleString()} sub={`${clusters.reduce((n, c) => n + (c.summary?.pods_running ?? 0), 0).toLocaleString()} running`} />
            <Kpi icon="alert" label="Failing pods" value={clusters.reduce((n, c) => n + (c.summary ? c.summary.pods_crashloop + c.summary.pods_failed : 0), 0)} tone={clusters.some(c => c.summary && c.summary.pods_crashloop + c.summary.pods_failed > 0) ? 'bad' : 'good'} />
          </div>
          <div className="tilegrid">
            {clusters.map(c => {
              const s = c.summary;
              const cpu = s?.cpu_m != null && s.cpu_alloc_m ? (s.cpu_m / s.cpu_alloc_m) * 100 : null;
              const mem = s?.mem_mib != null && s.mem_alloc_mib ? (s.mem_mib / s.mem_alloc_mib) * 100 : null;
              return (
                <div key={c.id} className="card tile" onClick={() => go(`kubernetes/${c.id}`)}>
                  <div className="tile-top"><span className="kpi-ico"><Icon name="k8s" size={16} /></span><div className="grow"><div className="name">{c.name}</div><small className="muted">{c.k8s_version || 'waiting for the agent'} · {s?.namespaces ?? 0} namespaces</small></div><StatusPill status={c.status} /></div>
                  {s ? (
                    <>
                      <div className="minis">
                        <div className="mini">Nodes<b>{s.nodes_ready}/{s.nodes_total}</b></div>
                        <div className="mini">Pods<b>{s.pods_running}/{s.pods_total}</b></div>
                        <div className="mini">Failing<b className={s.pods_crashloop + s.pods_failed ? 'bad' : ''}>{s.pods_crashloop + s.pods_failed}</b></div>
                      </div>
                      <div className="minis" style={{ gridTemplateColumns: '1fr 1fr' }}>
                        <div className="mini">CPU {cpu != null ? pct(cpu, 0) : '–'}{cpu != null ? <Meter value={cpu} warnAt={lim.warn} badAt={lim.bad} /> : <div className="bar" />}</div>
                        <div className="mini">Memory {mem != null ? pct(mem, 0) : '–'}{mem != null ? <Meter value={mem} warnAt={lim.warn} badAt={lim.bad} /> : <div className="bar" />}</div>
                      </div>
                      {s.problems.length > 0 && <div className="sm warn trunc" title={s.problems.join('\n')}>⚠ {s.problems[0]}{s.problems.length > 1 ? ` (+${s.problems.length - 1})` : ''}</div>}
                    </>
                  ) : <div className="muted sm" style={{ minHeight: 48 }}>{c.last_error || 'No report received yet.'}</div>}
                  <div className="foot"><span className="tag">agent {c.agent_version ? `v${c.agent_version}` : '–'}</span><span>seen {timeAgo(c.last_seen_at)}</span></div>
                </div>
              );
            })}
          </div>
        </>
      )}
      {route[1] === 'new' && canManage && <AddCluster onClose={() => { go('kubernetes'); void reload(); }} />}
    </>
  );
}

/* ---------------------------------------------------------------- add a cluster */
function AddCluster({ onClose }: { onClose: () => void }) {
  const lim = useLimits();
  const [name, setName] = useState('');
  const [base] = useControlPlaneUrl();
  const { active, error, busy, generate } = useActiveEnrollment();
  const valid = /^[A-Za-z0-9]([A-Za-z0-9._-]{0,58}[A-Za-z0-9])?$/.test(name);
  const cmd = active && valid ? `curl -fsSL -X POST "${base}/api/agent/k8s/${active.token}?name=${name}" | kubectl apply -f -` : '';
  return (
    <Modal title="Connect a Kubernetes cluster" onClose={onClose} wide>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <Field label="Cluster name" hint="Letters, digits, dots, dashes. e.g. prod-eu"><input value={name} onChange={e => setName(e.target.value.trim())} placeholder="prod-eu" maxLength={60} autoFocus /></Field>
        {error && <div className="err">{error}</div>}
        {!valid ? <span className="muted sm">Enter a valid name to get the install command.</span>
          : !active ? <div className="banner">An install link is created only when you need one and works for {lim.enrollDefault} minutes. <button className="btn sm primary" style={{ marginLeft: 8 }} disabled={busy} onClick={() => void generate('Kubernetes')}>Generate install command</button></div>
          : <><span className="sm muted">Run this with a kubeconfig that can create cluster roles (the link works for {lim.enrollDefault} minutes):</span><CodeBox value={cmd} /></>}
        <div className="card" style={{ background: 'var(--bg)' }}>
          <b className="sm">What gets installed</b>
          <ul className="sm muted" style={{ margin: '6px 0 0 18px' }}>
            <li>A <code>smwatch</code> namespace with one pod that only makes <b>outbound</b> HTTPS calls to this dashboard.</li>
            <li>A <b>read-only</b> ClusterRole: namespaces, nodes, pods, workloads, services, ingresses, HPAs, events, PVCs, metrics. <b>No Secrets, no ConfigMaps, no exec, no write access.</b></li>
            <li>The agent may update only its own token Secret, so a rotated token survives restarts.</li>
            <li>Nothing is shipped or stored: lists and logs are fetched on demand and discarded after {lim.logTtl} minutes.</li>
          </ul>
        </div>
        <span className="sm muted">Use an <b>https://</b> address for the dashboard. Review the manifest first with the same command without <code>| kubectl apply -f -</code>.</span>
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}><button className="btn" onClick={onClose}>Done</button></div>
      </div>
    </Modal>
  );
}

/* ---------------------------------------------------------------- cluster detail */
type TabId = 'overview' | 'workloads' | 'pods' | 'nodes' | 'scaling' | 'network' | 'storage' | 'events' | 'logs' | 'settings';
const TAB_ICON: Record<TabId, string> = { overview: 'overview', workloads: 'server', pods: 'k8s', nodes: 'server', scaling: 'zap', network: 'globe', storage: 'server', events: 'alert', logs: 'logs', settings: 'settings' };
const LIVE_CHOICES: [number, string][] = [[5000, '5 s'], [10000, '10 s'], [30000, '30 s'], [60000, '1 min'], [0, 'Off']];

function LivePill({ ms, setMs, updatedAt, now, onRefresh }: { ms: number; setMs: (v: number) => void; updatedAt: number | null; now: number; onRefresh: () => void }) {
  const ago = updatedAt ? Math.max(0, Math.round((now - updatedAt) / 1000)) : null;
  return (
    <div className={`livepill ${ms ? 'on' : ''}`}>
      <span className="livepill-dot" /><b>{ms ? 'Live' : 'Paused'}</b>
      <select value={ms} onChange={e => setMs(Number(e.target.value))} aria-label="Refresh every">{LIVE_CHOICES.map(([v, l]) => <option key={v} value={v}>{v ? `every ${l}` : 'Off'}</option>)}</select>
      <span className="livepill-ago">{ago == null ? 'loading…' : ago < 2 ? 'just updated' : `updated ${ago}s ago`}</span>
      <button className="btn ghost sm" onClick={onRefresh} aria-label="Refresh now" title="Refresh now"><Icon name="refresh" size={14} /></button>
    </div>
  );
}

function ClusterDetail({ cluster, reload }: { cluster: Cluster; reload: () => Promise<void> }) {
  const lim = useLimits();
  const { go, toast, canOperate, canManage, isAdmin, confirm } = useApp();
  const [tab, setTab] = useState<TabId>('overview');
  const [liveMs, setLiveMs] = useState(10000);
  const [tick, setTick] = useState(0);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [podsNs, setPodsNs] = useState('');
  const [stack, setStack] = useState<Target[]>([]);   // side panels: the last one is shown, Back returns to the one before
  const top = stack[stack.length - 1];
  const [logPreset, setLogPreset] = useState<{ ns: string; pod: string } | null>(null);
  useEffect(() => { try { const v = Number(localStorage.getItem('smw_k8s_live')); if ([0, 5000, 10000, 30000, 60000].includes(v) && localStorage.getItem('smw_k8s_live') !== null) setLiveMs(v); } catch { /* storage unavailable */ } }, []);
  const chooseLive = (v: number) => { setLiveMs(v); try { localStorage.setItem('smw_k8s_live', String(v)); } catch { /* ignore */ } };
  useEffect(() => { if (!liveMs) return; const t = setInterval(() => { if (!document.hidden) setTick(n => n + 1); }, liveMs); return () => clearInterval(t); }, [liveMs]);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  const touch = useCallback(() => setUpdatedAt(Date.now()), []);
  const liveValue = useMemo(() => ({ tick, ms: liveMs, touch }), [tick, liveMs, touch]);
  const openPanel = useCallback((t: Target) => setStack(s => (s.length && s[s.length - 1].resource === t.resource && s[s.length - 1].ns === t.ns && s[s.length - 1].name === t.name ? s : [...s.slice(-9), t])), []);
  const nav = useMemo<Nav>(() => ({ openPod: (ns, name) => setStack([{ resource: 'pod', ns, name }]), open: t => setStack([t]), goPods: ns => { setPodsNs(ns); setTab('pods'); } }), []);
  useEffect(() => { if (!stack.length) return; const k = (e: KeyboardEvent) => { if (e.key === 'Escape') setStack([]); }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [stack.length]);

  const tabs: [TabId, string][] = [['overview', 'Overview'], ['workloads', 'Workloads'], ['pods', 'Pods'], ['nodes', 'Nodes'], ['scaling', 'Autoscaling'], ['network', 'Network'], ['storage', 'Storage'], ['events', 'Events']];
  if (canOperate) tabs.push(['logs', 'Logs'], ['settings', 'Settings']);
  const offline = !cluster.last_seen_at || Date.now() - new Date(cluster.last_seen_at).getTime() > lim.offlineMs;

  async function remove() {
    if (!(await confirm(`Remove ${cluster.name}?\n\nIts history is deleted from SM-Watch. The agent inside the cluster is not uninstalled: delete the 'smwatch' namespace there.`))) return;
    try { await del(`/clusters/${cluster.id}`); toast('Cluster removed'); go('kubernetes'); } catch (e) { toast((e as Error).message, true); }
  }
  return (
    <LiveCtx.Provider value={liveValue}>
      <NavCtx.Provider value={nav}>
        <header className="khead">
          <button className="btn ghost sm" onClick={() => go('kubernetes')}><Icon name="back" size={15} />Clusters</button>
          <span className="khead-ico"><Icon name="k8s" size={20} /></span>
          <div className="khead-title"><h1>{cluster.name}</h1><div className="khead-sub"><StatusPill status={cluster.status} /><span className="tag">{cluster.k8s_version || 'unknown version'}</span><span className="muted sm">agent {cluster.agent_version ? `v${cluster.agent_version}` : '–'} · seen {timeAgo(cluster.last_seen_at)}</span></div></div>
          <span className="grow" />
          {!offline && <LivePill ms={liveMs} setMs={chooseLive} updatedAt={updatedAt} now={now} onRefresh={() => setTick(n => n + 1)} />}
          {canManage && <button className="btn sm danger" onClick={remove}>Remove</button>}
        </header>
        <div className="ktabs" role="tablist">{tabs.map(([id, label]) => <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}><Icon name={TAB_ICON[id]} size={15} />{label}</button>)}</div>
        {cluster.agent_outdated && cluster.latest_agent_version && <div style={{ marginBottom: 16 }}><ClusterAgentUpdate current={cluster.agent_version} latest={cluster.latest_agent_version} /></div>}
        {cluster.status !== 'up' && cluster.last_error && <div className="err" style={{ marginBottom: 16 }}>{cluster.last_error}</div>}
        {offline && tab !== 'overview' && tab !== 'settings' ? <div className="card"><Empty title="The cluster agent is offline">It has not reported for over {Math.round(lim.offlineMs / 60000) || 1} minute(s), so live data cannot be fetched. Check the <code>smwatch-agent</code> pod in the <code>smwatch</code> namespace.</Empty></div> : (
          <>
            {tab === 'overview' && <Overview cluster={cluster} />}
            {tab === 'workloads' && <Workloads cluster={cluster} />}
            {tab === 'pods' && <Pods cluster={cluster} initialNs={podsNs} />}
            {tab === 'nodes' && <Nodes cluster={cluster} />}
            {tab === 'scaling' && <Scaling cluster={cluster} />}
            {tab === 'network' && <Network cluster={cluster} />}
            {tab === 'storage' && <Storage cluster={cluster} />}
            {tab === 'events' && <Events cluster={cluster} />}
            {tab === 'logs' && canOperate && <PodLogs cluster={cluster} preset={logPreset} />}
            {tab === 'settings' && canOperate && <ClusterSettings cluster={cluster} isAdmin={isAdmin} reload={reload} />}
          </>
        )}
        {top && (
          <div className="drawer-overlay" onMouseDown={e => e.target === e.currentTarget && setStack([])}>
            {top.resource === 'pod'
              ? <PodDrawer key={`${top.ns}/${top.name}`} cluster={cluster} ns={top.ns} name={top.name} canLogs={canOperate && cluster.log_policy.enabled} onClose={() => setStack([])} onBack={stack.length > 1 ? () => setStack(s => s.slice(0, -1)) : undefined} open={openPanel}
                  onLogs={() => { setLogPreset({ ns: top.ns, pod: top.name }); setStack([]); setTab('logs'); }} />
              : <ResourceDrawer key={`${top.resource}/${top.ns}/${top.name}`} cluster={cluster} target={top} onClose={() => setStack([])} onBack={stack.length > 1 ? () => setStack(s => s.slice(0, -1)) : undefined} open={openPanel} />}
          </div>)}
      </NavCtx.Provider>
    </LiveCtx.Provider>
  );
}

const Stat = ({ label, value, sub, bad }: { label: string; value: ReactNode; sub?: ReactNode; bad?: boolean }) => (
  <div className="stat"><span className="label">{label}</span><span className={`value ${bad ? 'bad' : ''}`}>{value}</span>{sub && <span className="sub">{sub}</span>}</div>
);
const Loading = ({ busy, error, retry }: { busy: boolean; error: string; retry: () => void }) => error
  ? <div className="err" role="alert">{error} <button className="btn sm" onClick={retry}>Retry</button></div> : busy ? <p className="muted sm"><span className="spinner" /> Asking the cluster…</p> : null;
const Trunc = ({ on }: { on?: boolean }) => on ? <p className="sm warn">Showing the first rows only: narrow it with the namespace filter.</p> : null;

function NamespaceSelect({ cluster, value, onChange }: { cluster: Cluster; value: string; onChange: (v: string) => void }) {
  const ns = useCluster<Items<{ name: string }>>(cluster.id, { kind: 'namespaces' }, []);
  return (
    <select className="lv-select" value={value} onChange={e => onChange(e.target.value)} aria-label="Namespace">
      <option value="">All namespaces</option>{(ns.data?.data?.items ?? []).map(n => <option key={n.name} value={n.name}>{n.name}</option>)}
    </select>
  );
}

const mib = (v: number) => (v >= 1024 ? `${(v / 1024).toFixed(v >= 10240 ? 0 : 1)} GiB` : `${Math.round(v)} MiB`);
const cores = (m: number) => (m >= 1000 ? `${(m / 1000).toFixed(m >= 10000 ? 0 : 1)} cores` : `${Math.round(m)}m`);
const level = (p: number, warn: number, bad: number) => (p >= bad ? 'bad' : p >= warn ? 'warn' : 'good');

function Kpi({ icon, label, value, sub, tone, children }: { icon: string; label: string; value: ReactNode; sub?: ReactNode; tone?: 'good' | 'warn' | 'bad'; children?: ReactNode }) {
  return (
    <div className={`kpi ${tone ?? ''}`}>
      <div className="kpi-head"><span className="kpi-ico"><Icon name={icon} size={16} /></span><span className="kpi-label">{label}</span></div>
      <div className="kpi-value">{value}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
      {children}
    </div>
  );
}

function StackBar({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const total = parts.reduce((n, p) => n + p.value, 0) || 1;
  return (
    <div>
      <div className="stack">{parts.filter(p => p.value > 0).map(p => <i key={p.label} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} title={`${p.label}: ${p.value}`} />)}</div>
      <div className="stack-legend">{parts.map(p => <span key={p.label}><i style={{ background: p.color }} />{p.label} <b>{p.value}</b></span>)}</div>
    </div>
  );
}

/** A ring gauge: the share of something used, coloured by how worried to be. */
function Donut({ value, label, big, sub, tone }: { value: number | null; label: string; big: string; sub: string; tone: 'good' | 'warn' | 'bad' | 'info' }) {
  const R = 40, C = 2 * Math.PI * R, v = Math.max(0, Math.min(100, value ?? 0));
  return (
    <div className="donut">
      <svg viewBox="0 0 100 100" width="112" height="112" role="img" aria-label={`${label} ${big}`}>
        <circle cx="50" cy="50" r={R} fill="none" stroke="var(--surface-2)" strokeWidth="10" />
        {value != null && <circle cx="50" cy="50" r={R} fill="none" stroke={`var(--${tone === 'info' ? 'accent' : tone})`} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(v / 100) * C} ${C}`} transform="rotate(-90 50 50)" style={{ transition: 'stroke-dasharray .6s ease' }} />}
        <text x="50" y="52" textAnchor="middle" className="donut-big">{big}</text>
      </svg>
      <div className="donut-label">{label}</div><div className="donut-sub">{sub}</div>
    </div>
  );
}

type Rank = { name: string; sub: string; value: number; share?: number; click: () => void };
/** Top consumers: one card with switches instead of four lists. */
function Leaderboard({ pods, usage }: { pods: Pod[]; usage: PodUsage[] }) {
  const nav = useContext(NavCtx);
  const [metric, setMetric] = useState<'cpu' | 'mem' | 'restarts'>('cpu');
  const [group, setGroup] = useState<'pods' | 'namespaces'>('pods');
  const fmt = metric === 'cpu' ? cores : metric === 'mem' ? mib : (v: number) => `${v}×`;
  const color = metric === 'cpu' ? 'var(--c1)' : metric === 'mem' ? 'var(--c2)' : 'var(--warn)';
  const rows = useMemo<Rank[]>(() => {
    const use = new Map(usage.map(u => [`${u.ns}/${u.name}`, u]));
    const pick = (p: Pod) => { const u = use.get(`${p.ns}/${p.name}`); return metric === 'cpu' ? u?.cpu_m ?? 0 : metric === 'mem' ? u?.mem_mib ?? 0 : p.restarts; };
    if (group === 'pods') {
      const all = pods.map(p => ({ p, v: pick(p) })).filter(x => x.v > 0).sort((x, y) => y.v - x.v);
      const total = all.reduce((n, x) => n + x.v, 0) || 1;
      return all.slice(0, 8).map(x => ({ name: x.p.name, sub: x.p.ns, value: x.v, share: (x.v / total) * 100, click: () => nav.openPod(x.p.ns, x.p.name) }));
    }
    const by = new Map<string, number>(); const count = new Map<string, number>();
    for (const p of pods) { by.set(p.ns, (by.get(p.ns) ?? 0) + pick(p)); count.set(p.ns, (count.get(p.ns) ?? 0) + 1); }
    const all = [...by.entries()].filter(([, v]) => v > 0).sort((x, y) => y[1] - x[1]);
    const total = all.reduce((n, x) => n + x[1], 0) || 1;
    return all.slice(0, 8).map(([ns, v]) => ({ name: ns, sub: `${count.get(ns)} pods`, value: v, share: (v / total) * 100, click: () => nav.goPods(ns) }));
  }, [pods, usage, metric, group, nav]);
  const max = Math.max(1, ...rows.map(r => r.value));
  return (
    <section className="card">
      <div className="card-head"><h2>Top consumers</h2><span className="grow" />
        <div className="seg">{([['cpu', 'CPU'], ['mem', 'Memory'], ['restarts', 'Restarts']] as const).map(([id, l]) => <button key={id} className={metric === id ? 'on' : ''} onClick={() => setMetric(id)}>{l}</button>)}</div>
        <div className="seg">{([['pods', 'Pods'], ['namespaces', 'Namespaces']] as const).map(([id, l]) => <button key={id} className={group === id ? 'on' : ''} onClick={() => setGroup(id)}>{l}</button>)}</div>
      </div>
      {rows.length === 0 ? <p className="muted sm">{metric === 'restarts' ? 'No restarts. Nice.' : 'No usage data yet (needs metrics-server).'}</p> : (
        <ol className="rank">{rows.map((r, i) => (
          <li key={r.sub + r.name}>
            <button className="rank-row" onClick={r.click} title={`${r.sub}/${r.name}`}>
              <span className="rank-n">{i + 1}</span>
              <span className="rank-name"><b>{r.name}</b><small>{r.sub}</small></span>
              <span className="rank-bar"><i style={{ width: `${(r.value / max) * 100}%`, background: color }} /></span>
              <span className="rank-val">{fmt(r.value)}{r.share != null && metric !== 'restarts' && <small>{r.share.toFixed(0)}%</small>}</span>
            </button>
          </li>))}</ol>)}
    </section>
  );
}

/** Namespaces as tiles: bigger = more pods, warmer = more memory. */
function NamespaceHeat({ pods, usage }: { pods: Pod[]; usage: PodUsage[] }) {
  const nav = useContext(NavCtx);
  const tiles = useMemo(() => {
    const use = new Map(usage.map(u => [`${u.ns}/${u.name}`, u.mem_mib]));
    const by = new Map<string, { pods: number; bad: number; mem: number }>();
    for (const p of pods) { const t = by.get(p.ns) ?? { pods: 0, bad: 0, mem: 0 }; t.pods++; t.mem += use.get(`${p.ns}/${p.name}`) ?? 0; if (badPod(p.status)) t.bad++; by.set(p.ns, t); }
    const all = [...by.entries()].sort((a, b) => b[1].pods - a[1].pods).slice(0, 30);
    return { all, memMax: Math.max(1, ...all.map(([, t]) => t.mem)), podMax: Math.max(1, ...all.map(([, t]) => t.pods)) };
  }, [pods, usage]);
  if (tiles.all.length === 0) return null;
  return (
    <section className="card">
      <div className="card-head"><h2>Namespaces</h2><span className="grow" /><span className="sm muted">size = pods · colour = memory</span></div>
      <div className="heat">{tiles.all.map(([ns, t]) => {
        const warm = tiles.memMax > 1 ? t.mem / tiles.memMax : t.pods / tiles.podMax;
        return (
          <button key={ns} className={`heat-tile ${t.bad ? 'bad' : ''}`} style={{ flexGrow: Math.max(1, t.pods), flexBasis: `${70 + (t.pods / tiles.podMax) * 90}px`, background: `color-mix(in srgb, var(--c2) ${Math.round(8 + warm * 52)}%, var(--surface-2))` }} onClick={() => nav.goPods(ns)} title={`${ns}: ${t.pods} pods${t.mem ? `, ${mib(t.mem)}` : ''}${t.bad ? `, ${t.bad} unhealthy` : ''}`}>
            <b>{ns}</b><small>{t.pods} pod{t.pods === 1 ? '' : 's'}{t.mem ? ` · ${mib(t.mem)}` : ''}</small>{t.bad > 0 && <i className="heat-bad">{t.bad}</i>}
          </button>);
      })}</div>
    </section>
  );
}

function Overview({ cluster }: { cluster: Cluster }) {
  const lim = useLimits();
  const s = cluster.summary;
  const hist = usePoll(() => api<{ points: Point[]; samples: number }>(`/clusters/${cluster.id}/history?range=24h`), [cluster.id], 30000);
  const online = !!cluster.last_seen_at && Date.now() - new Date(cluster.last_seen_at).getTime() < lim.offlineMs;
  const go = online && !!s;
  const pods = useCluster<Items<Pod>>(go ? cluster.id : 0, go ? { kind: 'pods', limit: 500 } : null, [], 1);
  const podUse = useCluster<Items<PodUsage> & { available: boolean }>(go ? cluster.id : 0, go ? { kind: 'pod_metrics' } : null, [], 1);
  const nodes = useCluster<Items<NodeRow>>(go ? cluster.id : 0, go ? { kind: 'nodes' } : null, [], 1);
  const nodeUse = useCluster<Items<{ name: string; cpu_m: number; mem_mib: number }> & { available: boolean }>(go ? cluster.id : 0, go ? { kind: 'node_metrics' } : null, [], 1);
  const events = useCluster<Items<Ev>>(go ? cluster.id : 0, go ? { kind: 'events', warnings_only: true, limit: 8 } : null, [], 1);
  if (!s) return <div className="card"><Empty title="Waiting for the agent">No report has been received yet. Run the install command on a machine with kubectl access.</Empty></div>;

  const podList = pods.data?.data?.items ?? [];
  const nodeList = nodes.data?.data?.items ?? [];
  const usage = podUse.data?.data?.items ?? [];
  // Live numbers from the questions above when they have arrived; the agent's last report fills in until then.
  const livePods = pods.data != null;
  const phase = (p: Pod) => p.phase || (p.status === 'Running' ? 'Running' : '');
  const L = {
    nodesTotal: nodes.data ? nodeList.length : s.nodes_total, nodesReady: nodes.data ? nodeList.filter(n => n.ready).length : s.nodes_ready,
    podsTotal: livePods ? podList.length : s.pods_total, running: livePods ? podList.filter(p => phase(p) === 'Running').length : s.pods_running,
    pending: livePods ? podList.filter(p => phase(p) === 'Pending').length : s.pods_pending, failed: livePods ? podList.filter(p => phase(p) === 'Failed').length : s.pods_failed,
    done: livePods ? podList.filter(p => phase(p) === 'Succeeded').length : s.pods_succeeded, crash: livePods ? podList.filter(p => /CrashLoop/i.test(p.status)).length : s.pods_crashloop,
    restarts: livePods ? podList.reduce((n, p) => n + p.restarts, 0) : s.restarts,
    cpu: nodeUse.data?.data?.available ? (nodeUse.data.data.items ?? []).reduce((n, x) => n + x.cpu_m, 0) : s.cpu_m, mem: nodeUse.data?.data?.available ? (nodeUse.data.data.items ?? []).reduce((n, x) => n + x.mem_mib, 0) : s.mem_mib,
    cpuAlloc: nodes.data ? nodeList.reduce((n, x) => n + x.cpu_alloc_m, 0) : s.cpu_alloc_m, memAlloc: nodes.data ? nodeList.reduce((n, x) => n + x.mem_alloc_mib, 0) : s.mem_alloc_mib,
    podCap: nodes.data ? nodeList.reduce((n, x) => n + x.pods_cap, 0) : null,
  };
  const cpuPct = L.cpu != null && L.cpuAlloc ? (L.cpu / L.cpuAlloc) * 100 : null;
  const memPct = L.mem != null && L.memAlloc ? (L.mem / L.memAlloc) * 100 : null;
  const podPct = L.podCap ? (L.podsTotal / L.podCap) * 100 : null;
  const failing = L.crash + L.failed;
  const workloads = s.deployments_total + s.statefulsets_total + s.daemonsets_total;
  const unavailable = s.deployments_unavailable + s.statefulsets_unavailable + s.daemonsets_unavailable;
  const issues = s.problems.length;
  const points = hist.value?.points ?? [];
  const spark = (key: string) => points.map(p => Number(p[key] ?? 0)).filter(v => !isNaN(v));
  const noReq = podList.filter(p => p.status === 'Running' && !p.cpu_req_m && !p.mem_req_mib && !p.ns.startsWith('kube-')).length;
  const noLimit = podList.filter(p => p.status === 'Running' && !p.mem_lim_mib && !p.ns.startsWith('kube-')).length;

  return (
    <div className="grid">
      <section className={`khero ${cluster.status}`}>
        <span className="khero-ico"><Icon name={cluster.status === 'up' ? 'check' : 'alert'} size={22} /></span>
        <div style={{ minWidth: 0 }}>
          <div className="khero-title">{cluster.status === 'up' ? 'All systems healthy' : issues ? `${issues} issue${issues === 1 ? '' : 's'} need attention` : cluster.status === 'down' ? 'Agent is not reporting' : 'Degraded'}</div>
          <div className="khero-sub">{L.nodesReady}/{L.nodesTotal} nodes ready · {L.running}/{L.podsTotal} pods running · {workloads} workloads · {s.namespaces} namespaces · Kubernetes {cluster.k8s_version}</div>
        </div>
      </section>
      {s.problems.length > 0 && <section className="card" style={{ borderColor: 'color-mix(in srgb, var(--warn) 45%, var(--line))' }}><div className="card-head"><h2>Needs attention</h2></div><ul className="problems">{s.problems.map((p, i) => <li key={i} className="sm">{p}</li>)}</ul></section>}

      <div className="grid g-side">
        <section className="card">
          <div className="card-head"><h2>Capacity</h2><span className="grow" />{!nodeUse.data?.data?.available && nodeUse.data && <span className="sm muted">metrics-server not available: usage unknown</span>}</div>
          <div className="donuts">
            <Donut value={cpuPct} label="CPU" big={cpuPct != null ? pct(cpuPct, 0) : '–'} sub={L.cpu != null ? `${cores(L.cpu)} of ${cores(L.cpuAlloc ?? 0)}` : 'allocatable ' + cores(L.cpuAlloc ?? 0)} tone={cpuPct != null ? level(cpuPct, lim.warn, lim.bad) : 'info'} />
            <Donut value={memPct} label="Memory" big={memPct != null ? pct(memPct, 0) : '–'} sub={L.mem != null ? `${mib(L.mem)} of ${mib(L.memAlloc ?? 0)}` : 'allocatable ' + mib(L.memAlloc ?? 0)} tone={memPct != null ? level(memPct, lim.warn, lim.bad) : 'info'} />
            <Donut value={podPct} label="Pods" big={`${L.podsTotal}`} sub={L.podCap ? `of ${L.podCap} slots` : `${L.running} running`} tone={podPct != null ? level(podPct, 80, 95) : 'info'} />
            <Donut value={L.nodesTotal ? (L.nodesReady / L.nodesTotal) * 100 : null} label="Nodes ready" big={`${L.nodesReady}/${L.nodesTotal}`} sub={s.not_ready_nodes.length ? s.not_ready_nodes.join(', ') : 'all ready'} tone={L.nodesReady < L.nodesTotal ? 'bad' : 'good'} />
          </div>
        </section>
        <section className="card">
          <div className="card-head"><h2>Health</h2></div>
          <StackBar parts={[{ label: 'Running', value: L.running, color: 'var(--good)' }, { label: 'Pending', value: L.pending, color: 'var(--warn)' }, { label: 'Failed', value: L.failed, color: 'var(--bad)' }, { label: 'Completed', value: L.done, color: 'var(--info)' }]} />
          <div className="hrow"><span>Crash-looping pods</span><span className="grow" /><b className={failing ? 'bad' : 'good'}>{L.crash}</b></div>
          <div className="hrow"><span>Container restarts</span><span className="grow" /><b>{L.restarts.toLocaleString()}</b></div>
          <div className="hrow"><span>Workloads available</span><span className="grow" /><b className={unavailable ? 'bad' : 'good'}>{workloads - unavailable}/{workloads}</b></div>
          <div className="hrow"><span>Autoscalers (HPA)</span><span className="grow" /><b>{s.hpa_total}</b></div>
          {livePods && <div className="chips" style={{ marginTop: 10 }}>
            <span className={`chip ${noReq ? 'warn' : ''}`} title="Running pods with neither CPU nor memory requests">{noReq} without requests</span>
            <span className={`chip ${noLimit ? 'warn' : ''}`} title="Running pods without a memory limit">{noLimit} without memory limit</span></div>}
        </section>
      </div>

      <div className="kpis">
        <Kpi icon="k8s" label="Pods running" value={<>{L.running}<small>/{L.podsTotal}</small></>} tone={failing ? 'bad' : L.pending ? 'warn' : 'good'} sub={`${L.pending} pending · ${failing} failing · ${L.done} done`}><Sparkline values={spark('pods_running')} color="var(--good)" height={30} /></Kpi>
        <Kpi icon="overview" label="CPU used" value={L.cpu != null ? cores(L.cpu) : '–'} tone={cpuPct != null ? level(cpuPct, lim.warn, lim.bad) : undefined} sub={L.cpuAlloc ? `of ${cores(L.cpuAlloc)}` : undefined}><Sparkline values={spark('cpu_m')} color="var(--c1)" height={30} /></Kpi>
        <Kpi icon="logs" label="Memory used" value={L.mem != null ? mib(L.mem) : '–'} tone={memPct != null ? level(memPct, lim.warn, lim.bad) : undefined} sub={L.memAlloc ? `of ${mib(L.memAlloc)}` : undefined}><Sparkline values={spark('mem_mib')} color="var(--c2)" height={30} /></Kpi>
        <Kpi icon="alert" label="Recent warnings" value={events.data ? (events.data.data?.items ?? []).length : '–'} tone={(events.data?.data?.items ?? []).length ? 'warn' : 'good'} sub="newest warning events" />
      </div>

      <Leaderboard pods={podList} usage={usage} />
      <NamespaceHeat pods={podList} usage={usage} />

      <div className="grid g2">
        <section className="card"><div className="card-head"><h2>CPU, last 24 h</h2><span className="grow" />{L.cpu != null && <span className="sm muted">now {cores(L.cpu)}</span>}</div>
          <AreaChart points={points} height={150} series={[{ key: 'cpu_m', label: 'Used', color: 'var(--c1)', peakKey: 'cpu_m_max', format: v => cores(v) }]} />
          {L.cpuAlloc != null && <div className="sm muted" style={{ marginTop: 6 }}>Capacity {cores(L.cpuAlloc)}</div>}</section>
        <section className="card"><div className="card-head"><h2>Memory, last 24 h</h2><span className="grow" />{L.mem != null && <span className="sm muted">now {mib(L.mem)}</span>}</div>
          <AreaChart points={points} height={150} series={[{ key: 'mem_mib', label: 'Used', color: 'var(--c2)', peakKey: 'mem_mib_max', format: v => mib(v) }]} />
          {L.memAlloc != null && <div className="sm muted" style={{ marginTop: 6 }}>Capacity {mib(L.memAlloc)}</div>}</section>
      </div>

      {nodeList.length > 0 && (
        <section className="card"><div className="card-head"><h2>Nodes</h2></div>
          <div className="nodegrid">{nodeList.map(n => {
            const u = (nodeUse.data?.data?.items ?? []).find(x => x.name === n.name);
            const cp = u ? (u.cpu_m / n.cpu_alloc_m) * 100 : null, mp = u ? (u.mem_mib / n.mem_alloc_mib) * 100 : null;
            const nodeIssues = n.conditions.filter(c => (c.type === 'Ready' ? c.status !== 'True' : c.status === 'True'));
            const podsHere = podList.filter(p => p.node === n.name).length;
            return (
              <div key={n.name} className="nodecard">
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><b className="trunc" title={n.name}>{n.name}</b><span className="grow" /><StatusPill status={n.ready && !nodeIssues.length ? 'up' : 'alert'} label={n.ready ? (nodeIssues.length ? nodeIssues.map(i => i.type).join(', ') : 'Ready') : 'Not ready'} /></div>
                <div className="sm muted">{n.roles.join(', ')} · {n.version} · {n.ip}</div>
                <div className="nrow"><span>CPU</span>{cp != null ? <><Meter value={cp} warnAt={lim.warn} badAt={lim.bad} /><b>{pct(cp, 0)}</b></> : <span className="muted sm">{cores(n.cpu_alloc_m)}</span>}</div>
                <div className="nrow"><span>Memory</span>{mp != null ? <><Meter value={mp} warnAt={lim.warn} badAt={lim.bad} /><b>{pct(mp, 0)}</b></> : <span className="muted sm">{mib(n.mem_alloc_mib)}</span>}</div>
                <div className="nrow"><span>Pods</span><Meter value={(podsHere / Math.max(1, n.pods_cap)) * 100} warnAt={80} badAt={95} /><b>{podsHere}/{n.pods_cap}</b></div>
              </div>);
          })}</div>
        </section>)}

      <section className="card"><div className="card-head"><h2>Recent warnings</h2></div>
        {!events.data ? <p className="muted sm">{events.error || 'Loading…'}</p> : (events.data.data?.items ?? []).length === 0 ? <p className="muted sm">No warning events.</p> : (
          <div className="tbl-wrap"><table className="tbl"><tbody>{(events.data.data?.items ?? []).map((e, i) => <tr key={i}><td className="sm" style={{ whiteSpace: 'nowrap' }}>{timeAgo(e.last)}{e.count > 1 && <small> ×{e.count}</small>}</td><td className="warn"><b>{e.reason}</b></td><td className="sm mono">{e.ns ? `${e.ns}/` : ''}{e.object}</td><td className="sm">{e.message}</td></tr>)}</tbody></table></div>)}
      </section>
    </div>
  );
}

type Workload = { ns: string; name: string; desired: number; ready: number; updated: number; images: string[]; message: string; kind?: string };
type JobRow = { ns: string; name: string; state: string; succeeded: number; failed: number; completions: number | null; owner: string };
type CronRow = { ns: string; name: string; schedule: string; suspend: boolean; last: string | null; active: number };
function Workloads({ cluster }: { cluster: Cluster }) {
  const nav = useContext(NavCtx);
  const [ns, setNs] = useState('');
  const [filter, setFilter] = useState('');
  const [kind, setKind] = useState<'all' | 'Deployment' | 'StatefulSet' | 'DaemonSet' | 'problems'>('all');
  const dep = useCluster<Items<Workload>>(cluster.id, { kind: 'deployments', namespace: ns, limit: 500 }, [ns], 20000);
  const sts = useCluster<Items<Workload>>(cluster.id, { kind: 'statefulsets', namespace: ns, limit: 500 }, [ns], 20000);
  const dss = useCluster<Items<Workload>>(cluster.id, { kind: 'daemonsets', namespace: ns, limit: 500 }, [ns], 20000);
  const jobs = useCluster<Items<JobRow>>(cluster.id, { kind: 'jobs', namespace: ns, limit: 500 }, [ns], 30000);
  const crons = useCluster<Items<CronRow>>(cluster.id, { kind: 'cronjobs', namespace: ns, limit: 500 }, [ns], 30000);
  const all = [...(dep.data?.data?.items ?? []).map(r => ({ ...r, kind: 'Deployment' })), ...(sts.data?.data?.items ?? []).map(r => ({ ...r, kind: 'StatefulSet' })), ...(dss.data?.data?.items ?? []).map(r => ({ ...r, kind: 'DaemonSet' }))];
  const needle = filter.trim().toLowerCase();
  const match = (n: string, s2: string) => !needle || `${s2}/${n}`.toLowerCase().includes(needle);
  const rows = all.filter(r => match(r.name, r.ns) && (kind === 'all' || (kind === 'problems' ? r.ready < r.desired : r.kind === kind))).sort((a, b) => Number(b.ready < b.desired) - Number(a.ready < a.desired) || a.name.localeCompare(b.name));
  const jobRows = (jobs.data?.data?.items ?? []).filter(j => match(j.name, j.ns));
  const cronRows = (crons.data?.data?.items ?? []).filter(c => match(c.name, c.ns));
  const key = `${ns}|${needle}|${kind}`;
  const w = usePaged(rows, key), jp = usePaged(jobRows, key, 10), cp = usePaged(cronRows, key, 10);
  const count = (k: string) => all.filter(r => r.kind === k).length;
  return (
    <div className="grid">
      <div className="filterbar">
        <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
        <label className="lg-field grow" style={{ maxWidth: 320 }}><Icon name="logs" size={15} /><input placeholder="Filter by name…" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter workloads" />{filter && <button type="button" aria-label="Clear" onClick={() => setFilter('')}><Icon name="x" size={14} /></button>}</label>
        <div className="seg">{([['all', `All ${all.length}`], ['Deployment', `Deployments ${count('Deployment')}`], ['StatefulSet', `StatefulSets ${count('StatefulSet')}`], ['DaemonSet', `DaemonSets ${count('DaemonSet')}`], ['problems', `Not ready ${all.filter(r => r.ready < r.desired).length}`]] as const).map(([id, l]) => <button key={id} className={kind === id ? 'on' : ''} onClick={() => setKind(id)}>{l}</button>)}</div>
      </div>
      <section className="card"><div className="card-head"><h2>Deployments, StatefulSets & DaemonSets</h2><span className="grow" /><span className="muted sm">Click a row for its pods, services and events</span></div>
        <Loading busy={dep.busy && !dep.data} error={dep.error} retry={dep.reload} />
        {dep.data && (rows.length === 0 ? <p className="muted sm">None match.</p> : (
          <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Kind</th><th>Ready</th><th>Up-to-date</th><th className="hide-sm">Images</th></tr></thead><tbody>
            {w.rows.map(r => <tr key={`${r.kind}${r.ns}${r.name}`} className="click" onClick={() => nav.open({ resource: r.kind.toLowerCase(), ns: r.ns, name: r.name })}>
              <td><div className="name">{r.name}<small>{r.ns}</small></div></td><td className="sm">{r.kind}</td>
              <td className={r.ready < r.desired ? 'bad' : ''}><b>{r.ready}/{r.desired}</b></td><td>{r.updated}</td><td className="sm mono hide-sm">{r.images.map(i => i.split('/').pop()).join(', ')}{r.message && <div className="bad sm">{r.message}</div>}</td></tr>)}
          </tbody></table></div>))}
        {w.pager}<Trunc on={dep.data?.data?.truncated} />
      </section>
      <section className="card"><div className="card-head"><h2>Jobs</h2><span className="tag">{jobRows.length}</span></div>
        {jobs.data && (jobRows.length === 0 ? <p className="muted sm">No jobs.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>State</th><th>Succeeded</th><th>Failed</th></tr></thead><tbody>
          {jp.rows.map(j => <tr key={j.ns + j.name} className="click" onClick={() => nav.open({ resource: 'job', ns: j.ns, name: j.name })}><td><div className="name">{j.name}<small>{j.ns}{j.owner ? ` · ${j.owner}` : ''}</small></div></td><td className={j.state === 'Failed' ? 'bad' : ''}>{j.state}</td><td>{j.succeeded}{j.completions ? `/${j.completions}` : ''}</td><td className={j.failed ? 'bad' : ''}>{j.failed}</td></tr>)}</tbody></table></div>)}
        {jp.pager}
      </section>
      <section className="card"><div className="card-head"><h2>CronJobs</h2><span className="tag">{cronRows.length}</span></div>
        {crons.data && (cronRows.length === 0 ? <p className="muted sm">No cron jobs.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Schedule</th><th>Last run</th><th>Active</th></tr></thead><tbody>
          {cp.rows.map(c => <tr key={c.ns + c.name} className="click" onClick={() => nav.open({ resource: 'cronjob', ns: c.ns, name: c.name })}><td><div className="name">{c.name}<small>{c.ns}</small></div></td><td className="mono sm">{c.schedule}{c.suspend && <span className="tag">suspended</span>}</td><td>{timeAgo(c.last)}</td><td>{c.active}</td></tr>)}</tbody></table></div>)}
        {cp.pager}
      </section>
    </div>
  );
}

type Pod = { ns: string; name: string; status: string; phase?: string; ready: string; restarts: number; node: string; ip: string; created: string | null; owner: string; qos: string;
  containers: { name: string; image: string; ready: boolean; restarts: number; state: string; reason: string }[]; cpu_req_m: number; mem_req_mib: number; cpu_lim_m: number; mem_lim_mib: number };
type PodUsage = { ns: string; name: string; cpu_m: number; mem_mib: number };
const badPod = (s: string) => /CrashLoop|Error|ImagePull|ErrImage|Failed|OOMKilled|Evicted|Unknown|CreateContainer|Invalid/i.test(s);

const podTone = (status: string) => (status === 'Running' ? 'ok' : /Completed|Succeeded/.test(status) ? 'muted' : badPod(status) ? 'bad' : 'warn');
const ageOf = (iso: string | null) => (iso ? timeAgo(iso).replace(' ago', '') : '–');

/** A usage bar against a limit (or just the number when there is no limit to compare to). */
function UseBar({ value, limit, text }: { value: number | undefined; limit: number; text: string }) {
  const lim = useLimits();
  if (value == null) return <span className="muted">–</span>;
  const p = limit ? (value / limit) * 100 : null;
  return <span className="usebar"><span className="usebar-text">{text}</span>{p != null && <span className={`usebar-track ${p >= lim.bad ? 'bad' : p >= lim.warn ? 'warn' : ''}`}><i style={{ width: `${Math.min(100, p)}%` }} /></span>}</span>;
}

function Pods({ cluster, initialNs = '' }: { cluster: Cluster; initialNs?: string }) {
  const nav = useContext(NavCtx);
  const [ns, setNs] = useState(initialNs);
  const [filter, setFilter] = useState('');
  const [view, setView] = useState<'all' | 'problems' | 'restarts'>('all');
  const pods = useCluster<Items<Pod>>(cluster.id, { kind: 'pods', namespace: ns, limit: 500 }, [ns], 1);
  const usage = useCluster<Items<PodUsage> & { available: boolean; reason?: string }>(cluster.id, { kind: 'pod_metrics', namespace: ns }, [ns], 1);
  const u = new Map((usage.data?.data?.items ?? []).map(x => [`${x.ns}/${x.name}`, x]));
  const all = pods.data?.data?.items ?? [];
  const problems = all.filter(p => badPod(p.status)).length, restarted = all.filter(p => p.restarts > 5).length;
  const rows = all.filter(p => (!filter || `${p.ns}/${p.name}`.toLowerCase().includes(filter.toLowerCase())) && (view === 'all' || (view === 'problems' ? badPod(p.status) : p.restarts > 5)))
    .sort((a, b) => Number(badPod(b.status)) - Number(badPod(a.status)) || b.restarts - a.restarts);
  const paged = usePaged(rows, `${ns}|${filter}|${view}`);
  return (
    <div className="grid">
      <div className="filterbar">
        <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
        <label className="lg-field grow" style={{ maxWidth: 360 }}><Icon name="logs" size={15} /><input placeholder="Filter pods by name…" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter pods" />{filter && <button type="button" aria-label="Clear" onClick={() => setFilter('')}><Icon name="x" size={14} /></button>}</label>
        <div className="seg">{([['all', `All ${all.length}`], ['problems', `Problems ${problems}`], ['restarts', `Restarting ${restarted}`]] as const).map(([id, l]) => <button key={id} className={view === id ? 'on' : ''} onClick={() => setView(id)}>{l}</button>)}</div>
        <span className="grow" /><button className="btn sm" onClick={() => { pods.reload(); usage.reload(); }}><Icon name="refresh" size={14} />Refresh</button>
      </div>
      {usage.data && usage.data.data?.available === false && <p className="sm muted">{usage.data.data.reason} Usage columns are empty.</p>}
      <section className="card flush">
        <Loading busy={pods.busy && !pods.data} error={pods.error} retry={pods.reload} />
        {pods.data && (rows.length === 0 ? <div style={{ padding: 18 }}><p className="muted sm">No pods match.</p></div> : (
          <div className="tbl-wrap"><table className="tbl ktbl"><thead><tr><th>Pod</th><th>Status</th><th>Ready</th><th className="num">Restarts</th><th>CPU</th><th>Memory</th><th className="hide-sm">Node</th><th className="num hide-sm">Age</th></tr></thead><tbody>
            {paged.rows.map(p => { const x = u.get(`${p.ns}/${p.name}`); return (
              <tr key={p.ns + p.name} className="click" onClick={() => nav.openPod(p.ns, p.name)}>
                <td><div className="podname"><b title={p.name}>{p.name}</b><span className="nschip">{p.ns}</span></div></td>
                <td><span className={`kstatus ${podTone(p.status)}`}><i />{p.status}</span></td>
                <td className="sm">{p.ready}</td>
                <td className="num">{p.restarts > 0 ? <span className={`rbadge ${p.restarts > 20 ? 'bad' : p.restarts > 5 ? 'warn' : ''}`}>{p.restarts}</span> : <span className="muted">0</span>}</td>
                <td><UseBar value={x?.cpu_m} limit={p.cpu_lim_m} text={x ? `${Math.round(x.cpu_m)}m` : ''} /></td>
                <td><UseBar value={x?.mem_mib} limit={p.mem_lim_mib} text={x ? mib(x.mem_mib) : ''} /></td>
                <td className="sm hide-sm trunc" style={{ maxWidth: 160 }} title={p.node}>{p.node}</td><td className="num sm hide-sm">{ageOf(p.created)}</td></tr>); })}
          </tbody></table></div>))}
        <div style={{ padding: '0 14px' }}>{paged.pager}</div>
        <Trunc on={pods.data?.data?.truncated} />
      </section>
    </div>
  );
}

type PodObject = { metadata?: { labels?: Record<string, string>; ownerReferences?: { kind: string; name: string }[]; creationTimestamp?: string };
  spec?: { nodeName?: string; containers?: { name: string; image: string; ports?: { containerPort: number; protocol?: string }[]; resources?: { requests?: Record<string, string>; limits?: Record<string, string> } }[]; serviceAccountName?: string };
  status?: { phase?: string; podIP?: string; hostIP?: string; qosClass?: string; startTime?: string; conditions?: { type: string; status: string; reason?: string; message?: string }[];
    containerStatuses?: { name: string; ready: boolean; restartCount: number; state?: Record<string, { reason?: string; message?: string; startedAt?: string; exitCode?: number }>; lastState?: Record<string, { reason?: string; exitCode?: number; finishedAt?: string }> }[] } };

/** The side panel for one pod: what it is, its containers, why it is unhealthy, and a shortcut to its logs. */
function PodDrawer({ cluster, ns, name, canLogs, onClose, onLogs, onBack, open }: { cluster: Cluster; ns: string; name: string; canLogs: boolean; onClose: () => void; onLogs: () => void; onBack?: () => void; open: (t: Target) => void }) {
  const target = useMemo(() => ({ resource: 'pod', ns, name }), [ns, name]);
  const d = useRelated(cluster, target);
  const { toast } = useApp();
  const o = d.data?.data?.object as PodObject | undefined;
  const phase = o?.status?.phase ?? '';
  const statuses = new Map((o?.status?.containerStatuses ?? []).map(c => [c.name, c]));
  const owner = o?.metadata?.ownerReferences?.[0];
  const stateOf = (c?: NonNullable<PodObject['status']>['containerStatuses'] extends (infer T)[] | undefined ? T : never) => {
    const st = c?.state ? Object.entries(c.state)[0] : undefined;
    return st ? { kind: st[0], reason: st[1]?.reason ?? '', message: st[1]?.message ?? '' } : { kind: 'unknown', reason: '', message: '' };
  };
  return (
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Pod ${name}`}>
        <div className="drawer-head">
          {onBack && <button className="btn ghost sm" onClick={onBack} aria-label="Back"><Icon name="back" size={15} /></button>}
          <div style={{ minWidth: 0 }}><div className="sm muted">Pod · <span className="nschip">{ns}</span></div><h2 className="trunc" title={name}>{name}</h2></div>
          <span className="grow" /><button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
        </div>
        <div className="drawer-actions">
          {phase && <span className={`kstatus ${podTone(phase)}`}><i />{phase}</span>}
          {canLogs && <button className="btn primary sm" onClick={onLogs}><Icon name="logs" size={14} />View logs</button>}
          <button className="btn sm" onClick={() => { void navigator.clipboard?.writeText(`kubectl -n ${ns} describe pod ${name}`); toast('kubectl command copied'); }}>Copy kubectl describe</button>
        </div>
        <div className="drawer-body">
          <Loading busy={d.busy && !d.data} error={d.legacy ? '' : d.error} retry={d.reload} />
          {o && <>
            <div className="facts">
              <div><small>Node</small><b>{o.spec?.nodeName ?? '–'}</b></div><div><small>Pod IP</small><b className="mono">{o.status?.podIP ?? '–'}</b></div>
              <div><small>Owner</small><b>{owner ? `${owner.kind}/${owner.name}` : '–'}</b></div><div><small>QoS</small><b>{o.status?.qosClass ?? '–'}</b></div>
              <div><small>Started</small><b>{o.status?.startTime ? timeAgo(o.status.startTime).replace(' ago', ' ago') : '–'}</b></div><div><small>Service account</small><b>{o.spec?.serviceAccountName ?? '–'}</b></div>
            </div>
            <h3 className="drawer-h">Containers</h3>
            {(o.spec?.containers ?? []).map(c => { const cs = statuses.get(c.name); const st = stateOf(cs); const lastTerm = cs?.lastState?.terminated; return (
              <div key={c.name} className="ctr">
                <div className="ctr-head"><b>{c.name}</b><span className={`kstatus ${st.kind === 'running' ? 'ok' : st.kind === 'terminated' && !st.reason.match(/Error|OOM/i) ? 'muted' : st.kind === 'waiting' ? 'warn' : 'bad'}`}><i />{st.kind === 'running' ? 'Running' : st.reason || st.kind}</span>
                  {cs && cs.restartCount > 0 && <span className={`rbadge ${cs.restartCount > 20 ? 'bad' : 'warn'}`}>{cs.restartCount} restarts</span>}</div>
                <div className="sm muted mono trunc" title={c.image}>{c.image}</div>
                <div className="ctr-res">
                  <span>CPU <b>{c.resources?.requests?.cpu ?? '–'}</b> / <b>{c.resources?.limits?.cpu ?? 'no limit'}</b></span>
                  <span>Memory <b>{c.resources?.requests?.memory ?? '–'}</b> / <b>{c.resources?.limits?.memory ?? 'no limit'}</b></span>
                  {c.ports?.length ? <span>Ports <b>{c.ports.map(p => p.containerPort).join(', ')}</b></span> : null}</div>
                {(st.message || lastTerm) && <div className="ctr-why">{st.message && <p>{st.message}</p>}{lastTerm && <p>Last exit: <b>{lastTerm.reason ?? 'terminated'}</b>{lastTerm.exitCode != null ? ` (code ${lastTerm.exitCode})` : ''}{lastTerm.finishedAt ? ` · ${timeAgo(lastTerm.finishedAt)}` : ''}</p>}</div>}
              </div>); })}
            {(o.status?.conditions ?? []).some(c => c.status !== 'True') && <><h3 className="drawer-h">Conditions</h3>
              {(o.status?.conditions ?? []).filter(c => c.status !== 'True').map(c => <div key={c.type} className="sm" style={{ marginBottom: 6 }}><b className="warn">{c.type}</b> {c.reason}{c.message ? `: ${c.message}` : ''}</div>)}</>}
            {d.data?.data && <RelatedBlock data={d.data.data} open={open} self={target} />}
            <h3 className="drawer-h">Events</h3>
            <EventList events={d.data?.data?.events ?? []} empty="No events for this pod (Kubernetes keeps events for about an hour)." />
            {o.metadata?.labels && Object.keys(o.metadata.labels).length > 0 && <><h3 className="drawer-h">Labels</h3><div className="chips">{Object.entries(o.metadata.labels).slice(0, 14).map(([k, v]) => <span key={k} className="chip mono" title={`${k}=${v}`}>{k.split('/').pop()}={v.length > 24 ? `${v.slice(0, 22)}…` : v}</span>)}</div></>}
          </>}
        </div>
      </aside>
  );
}

type NodeRow = { name: string; ready: boolean; roles: string[]; version: string; os: string; kernel: string; runtime: string; arch: string; ip: string; unschedulable: boolean; taints: number;
  cpu_alloc_m: number; mem_alloc_mib: number; pods_cap: number; conditions: { type: string; status: string; reason: string; message: string }[] };
function Nodes({ cluster }: { cluster: Cluster }) {
  const lim = useLimits();
  const nav = useContext(NavCtx);
  const nodes = useCluster<Items<NodeRow>>(cluster.id, { kind: 'nodes' }, [], 20000);
  const usage = useCluster<Items<{ name: string; cpu_m: number; mem_mib: number }> & { available: boolean }>(cluster.id, { kind: 'node_metrics' }, [], 20000);
  const u = new Map((usage.data?.data?.items ?? []).map(x => [x.name, x]));
  const paged = usePaged(nodes.data?.data?.items ?? [], '');
  return (
    <section className="card">
      <Loading busy={nodes.busy && !nodes.data} error={nodes.error} retry={nodes.reload} />
      {nodes.data && <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Node</th><th>Status</th><th>Roles</th><th style={{ minWidth: 130 }}>CPU</th><th style={{ minWidth: 130 }}>Memory</th><th>Version</th><th>Address</th></tr></thead><tbody>
        {paged.rows.map(n => { const x = u.get(n.name); const cp = x ? (x.cpu_m / n.cpu_alloc_m) * 100 : null; const mp = x ? (x.mem_mib / n.mem_alloc_mib) * 100 : null; const issues = n.conditions.filter(c => (c.type === 'Ready' ? c.status !== 'True' : c.status === 'True')); return (
          <tr key={n.name} className="click" onClick={() => nav.open({ resource: 'node', ns: '', name: n.name })}>
            <td><div className="name">{n.name}<small>{n.os}</small></div></td>
            <td><StatusPill status={n.ready && !issues.length ? 'up' : 'alert'} label={n.ready ? (issues.length ? issues.map(i => i.type).join(', ') : 'Ready') : 'Not ready'} />{n.unschedulable && <span className="tag">cordoned</span>}</td>
            <td className="sm">{n.roles.join(', ')}</td>
            <td>{cp != null ? <><div className="sm">{Math.round(x!.cpu_m)}m / {Math.round(n.cpu_alloc_m)}m</div><Meter value={cp} warnAt={lim.warn} badAt={lim.bad} /></> : <span className="muted sm">{Math.round(n.cpu_alloc_m)}m allocatable</span>}</td>
            <td>{mp != null ? <><div className="sm">{Math.round(x!.mem_mib)} / {Math.round(n.mem_alloc_mib)} MiB</div><Meter value={mp} warnAt={lim.warn} badAt={lim.bad} /></> : <span className="muted sm">{Math.round(n.mem_alloc_mib)} MiB allocatable</span>}</td>
            <td className="sm mono">{n.version}</td><td className="sm mono">{n.ip}</td></tr>); })}
      </tbody></table></div>}
      {paged.pager}
      {usage.data && usage.data.data?.available === false && <p className="sm muted">Live usage needs metrics-server in the cluster.</p>}
    </section>
  );
}

type Hpa = { ns: string; name: string; target: string; min: number; max: number; current: number; desired: number; metrics: { name?: string; current?: string; target?: string; type?: string }[] | string[]; last_scale: string | null; conditions: { type: string; status: string; reason: string; message: string }[] };
function Scaling({ cluster }: { cluster: Cluster }) {
  const nav = useContext(NavCtx);
  const [ns, setNs] = useState('');
  const hpa = useCluster<Items<Hpa>>(cluster.id, { kind: 'hpa', namespace: ns, limit: 500 }, [ns], 20000);
  const fmt = (m: Hpa['metrics'][number]) => typeof m === 'string' ? m : `${m.name ?? m.type}: ${m.current ?? '?'} / ${m.target ?? '?'}`;
  const paged = usePaged(hpa.data?.data?.items ?? [], ns);
  return (
    <div className="grid">
      <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
      <section className="card"><div className="card-head"><h2>Horizontal Pod Autoscalers</h2></div>
        <Loading busy={hpa.busy && !hpa.data} error={hpa.error} retry={hpa.reload} />
        {hpa.data && ((hpa.data.data?.items ?? []).length === 0 ? <p className="muted sm">No HPAs in this scope.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Target</th><th>Replicas</th><th>Metrics (current / target)</th><th>Last scaled</th></tr></thead><tbody>
          {paged.rows.map(h => { const limited = h.conditions.find(c => c.type === 'ScalingLimited' && c.status === 'True'); const broken = h.conditions.find(c => c.type === 'ScalingActive' && c.status === 'False'); return (
            <tr key={h.ns + h.name} className="click" onClick={() => nav.open({ resource: 'hpa', ns: h.ns, name: h.name })}><td><div className="name">{h.name}<small>{h.ns}</small></div></td><td className="sm">{h.target}</td>
              <td><b className={h.current >= h.max ? 'warn' : ''}>{h.current}</b> <span className="muted sm">(want {h.desired}; {h.min}–{h.max})</span>{limited && <div className="warn sm">{limited.reason}</div>}</td>
              <td className="sm">{(h.metrics as Hpa['metrics']).length ? (h.metrics as Hpa['metrics'][number][]).map((m, i) => <div key={i}>{fmt(m)}</div>) : <span className="muted">none</span>}{broken && <div className="bad sm">{broken.message || broken.reason}</div>}</td>
              <td className="sm">{timeAgo(h.last_scale)}</td></tr>); })}
        </tbody></table></div>)}
        {paged.pager}
      </section>
    </div>
  );
}

function FilterRow({ cluster, ns, setNs, filter, setFilter, placeholder }: { cluster: Cluster; ns: string; setNs: (v: string) => void; filter: string; setFilter: (v: string) => void; placeholder: string }) {
  return (
    <div className="filterbar">
      <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
      <label className="lg-field grow" style={{ maxWidth: 320 }}><Icon name="logs" size={15} /><input placeholder={placeholder} value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter" />{filter && <button type="button" aria-label="Clear" onClick={() => setFilter('')}><Icon name="x" size={14} /></button>}</label>
    </div>
  );
}
const byName = (needle: string) => (r: { ns: string; name: string }) => !needle || `${r.ns}/${r.name}`.toLowerCase().includes(needle.trim().toLowerCase());

type IngRow = { ns: string; name: string; class: string; hosts: string[]; address: string[]; tls: number };
function Network({ cluster }: { cluster: Cluster }) {
  const nav = useContext(NavCtx);
  const [ns, setNs] = useState('');
  const [filter, setFilter] = useState('');
  const svc = useCluster<Items<SvcRow>>(cluster.id, { kind: 'services', namespace: ns, limit: 500 }, [ns], 30000);
  const ing = useCluster<Items<IngRow>>(cluster.id, { kind: 'ingresses', namespace: ns, limit: 500 }, [ns], 30000);
  const services = (svc.data?.data?.items ?? []).filter(byName(filter)), ingresses = (ing.data?.data?.items ?? []).filter(byName(filter));
  const sp = usePaged(services, `${ns}|${filter}`), ip = usePaged(ingresses, `${ns}|${filter}`, 10);
  return (
    <div className="grid">
      <FilterRow cluster={cluster} ns={ns} setNs={setNs} filter={filter} setFilter={setFilter} placeholder="Filter services and ingresses…" />
      <section className="card"><div className="card-head"><h2>Services</h2><span className="tag">{services.length}</span><span className="grow" /><span className="muted sm">Click a service for its pods and events</span></div>
        <Loading busy={svc.busy && !svc.data} error={svc.error} retry={svc.reload} />
        {svc.data && (services.length === 0 ? <p className="muted sm">No services.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Type</th><th>Cluster IP</th><th className="hide-sm">External</th><th>Ports</th></tr></thead><tbody>
          {sp.rows.map(s => <tr key={s.ns + s.name} className="click" onClick={() => nav.open({ resource: 'service', ns: s.ns, name: s.name })}><td><div className="name">{s.name}<small>{s.ns}</small></div></td><td className="sm">{s.type}</td><td className="mono sm">{s.cluster_ip}</td><td className="mono sm hide-sm">{s.external.join(', ') || '–'}</td><td className="mono sm">{s.ports.join(', ')}</td></tr>)}</tbody></table></div>)}
        {sp.pager}
      </section>
      <section className="card"><div className="card-head"><h2>Ingresses</h2><span className="tag">{ingresses.length}</span></div>
        {ing.data && (ingresses.length === 0 ? <p className="muted sm">No ingresses.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Class</th><th>Hosts</th><th className="hide-sm">Address</th><th>TLS</th></tr></thead><tbody>
          {ip.rows.map(i => <tr key={i.ns + i.name} className="click" onClick={() => nav.open({ resource: 'ingress', ns: i.ns, name: i.name })}><td><div className="name">{i.name}<small>{i.ns}</small></div></td><td className="sm">{i.class || '–'}</td><td className="mono sm">{i.hosts.join(', ')}</td><td className="mono sm hide-sm">{i.address.join(', ') || '–'}</td><td>{i.tls ? 'yes' : 'no'}</td></tr>)}</tbody></table></div>)}
        {ip.pager}
      </section>
    </div>
  );
}

type PvcRow = { ns: string; name: string; status: string; capacity: string; class: string; volume: string };
function Storage({ cluster }: { cluster: Cluster }) {
  const nav = useContext(NavCtx);
  const [ns, setNs] = useState('');
  const [filter, setFilter] = useState('');
  const pvc = useCluster<Items<PvcRow>>(cluster.id, { kind: 'pvcs', namespace: ns, limit: 500 }, [ns], 30000);
  const quotas = useCluster<Items<{ ns: string; name: string; resources: { name: string; hard: string; used: string }[] }>>(cluster.id, { kind: 'quotas', namespace: ns }, [ns], 60000);
  const claims = (pvc.data?.data?.items ?? []).filter(byName(filter));
  const unbound = claims.filter(c => c.status !== 'Bound').length;
  const quotaRows = (quotas.data?.data?.items ?? []).filter(byName(filter)).flatMap(q => q.resources.map(r => ({ ...r, ns: q.ns, quota: q.name })));
  const pp = usePaged(claims, `${ns}|${filter}`), qp = usePaged(quotaRows, `${ns}|${filter}`, 10);
  const classes = new Map<string, number>();
  claims.forEach(c => classes.set(c.class || 'default', (classes.get(c.class || 'default') ?? 0) + 1));
  return (
    <div className="grid">
      <FilterRow cluster={cluster} ns={ns} setNs={setNs} filter={filter} setFilter={setFilter} placeholder="Filter volume claims…" />
      <div className="ssh-stats">
        <div className="card ssh-stat"><small>Volume claims</small><b>{pvc.data ? claims.length : '–'}</b><span className="muted sm">in this scope</span></div>
        <div className="card ssh-stat"><small>Not bound</small><b className={unbound ? 'warn' : ''}>{pvc.data ? unbound : '–'}</b><span className="muted sm">pending or lost claims</span></div>
        <div className="card ssh-stat"><small>Storage classes</small><b className="sm-b">{[...classes.keys()].join(', ') || '–'}</b><span className="muted sm">{[...classes.values()].join(' / ')}</span></div>
      </div>
      <section className="card"><div className="card-head"><h2>Persistent volume claims</h2><span className="grow" /><span className="muted sm">Click a claim to see which pods use it</span></div>
        <Loading busy={pvc.busy && !pvc.data} error={pvc.error} retry={pvc.reload} />
        {pvc.data && (claims.length === 0 ? <p className="muted sm">No claims.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Status</th><th>Capacity</th><th>Class</th><th className="hide-sm">Volume</th></tr></thead><tbody>
          {pp.rows.map(p => <tr key={p.ns + p.name} className="click" onClick={() => nav.open({ resource: 'pvc', ns: p.ns, name: p.name })}><td><div className="name">{p.name}<small>{p.ns}</small></div></td><td className={p.status !== 'Bound' ? 'warn' : ''}>{p.status}</td><td>{p.capacity || '–'}</td><td className="sm">{p.class}</td><td className="mono sm hide-sm">{p.volume}</td></tr>)}</tbody></table></div>)}
        {pp.pager}
      </section>
      {quotaRows.length > 0 && <section className="card"><div className="card-head"><h2>Resource quotas</h2></div><div className="tbl-wrap"><table className="tbl"><thead><tr><th>Quota</th><th>Resource</th><th className="num">Used / limit</th></tr></thead><tbody>
        {qp.rows.map(r => <tr key={r.ns + r.quota + r.name}><td className="sm">{r.ns}/{r.quota}</td><td className="mono sm">{r.name}</td><td className="num">{r.used} / {r.hard}</td></tr>)}</tbody></table></div>{qp.pager}</section>}
    </div>
  );
}

type Ev = { ns: string; type: string; reason: string; object: string; message: string; count: number; last: string | null };
function Events({ cluster }: { cluster: Cluster }) {
  const nav = useContext(NavCtx);
  const [ns, setNs] = useState('');
  const [warn, setWarn] = useState(true);
  const [filter, setFilter] = useState('');
  const ev = useCluster<Items<Ev>>(cluster.id, { kind: 'events', namespace: ns, warnings_only: warn, limit: 500 }, [ns, warn], 20000);
  const needle = filter.trim().toLowerCase();
  const rows = (ev.data?.data?.items ?? []).filter(e => !needle || `${e.ns} ${e.object} ${e.reason} ${e.message}`.toLowerCase().includes(needle));
  const paged = usePaged(rows, `${ns}|${warn}|${needle}`);
  const openObject = (e: Ev) => { const [k, n] = e.object.split('/'); const res = RESOURCE_OF[k]; if (res && n) nav.open({ resource: res, ns: res === 'node' ? '' : e.ns, name: n }); };
  return (
    <div className="grid">
      <div className="filterbar"><NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
        <label className="lg-field grow" style={{ maxWidth: 320 }}><Icon name="logs" size={15} /><input placeholder="Filter reason, object, message…" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter events" /></label>
        <label className="check"><input type="checkbox" checked={warn} onChange={e => setWarn(e.target.checked)} />Warnings only</label></div>
      <section className="card"><Loading busy={ev.busy && !ev.data} error={ev.error} retry={ev.reload} />
        {ev.data && (rows.length === 0 ? <p className="muted sm">No events.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>When</th><th>Reason</th><th>Object</th><th>Message</th></tr></thead><tbody>
          {paged.rows.map((e, i) => <tr key={i} className={RESOURCE_OF[e.object.split('/')[0]] ? 'click' : ''} onClick={() => openObject(e)}><td className="sm">{timeAgo(e.last)}{e.count > 1 && <small> ×{e.count}</small>}</td><td className={e.type === 'Warning' ? 'warn' : ''}><b>{e.reason}</b></td><td className="sm mono">{e.ns ? `${e.ns}/` : ''}{e.object}</td><td className="sm">{e.message}</td></tr>)}</tbody></table></div>)}
        {paged.pager}
      </section>
    </div>
  );
}

/* ---------------------------------------------------------------- pagination (every resource list) */
const PAGE_SIZES = [10, 25, 50, 100];
function Pager({ page, pages, size, total, onPage, onSize }: { page: number; pages: number; size: number; total: number; onPage: (p: number) => void; onSize: (s: number) => void }) {
  if (total <= PAGE_SIZES[0]) return null;
  const nums: (number | '…')[] = [];
  for (let i = 0; i < pages; i++) if (i === 0 || i === pages - 1 || Math.abs(i - page) <= 1) nums.push(i); else if (nums[nums.length - 1] !== '…') nums.push('…');
  return (
    <nav className="pager" aria-label="Pages">
      <span className="muted sm">{(page * size + 1).toLocaleString()}–{Math.min(total, (page + 1) * size).toLocaleString()} of {total.toLocaleString()}</span>
      <span className="grow" />
      <select className="lg-mini" value={size} onChange={e => onSize(Number(e.target.value))} aria-label="Rows per page">{PAGE_SIZES.map(n => <option key={n} value={n}>{n} / page</option>)}</select>
      <button type="button" onClick={() => onPage(page - 1)} disabled={page === 0} aria-label="Previous page">‹</button>
      {nums.map((n, i) => n === '…' ? <span key={`e${i}`} className="muted">…</span> : <button type="button" key={n} className={n === page ? 'on' : ''} aria-current={n === page ? 'page' : undefined} onClick={() => onPage(n)}>{n + 1}</button>)}
      <button type="button" onClick={() => onPage(page + 1)} disabled={page >= pages - 1} aria-label="Next page">›</button>
    </nav>
  );
}
/** Slices `rows` into pages. The page resets whenever `resetKey` (filters, namespace) or the page size changes. */
function usePaged<T>(rows: T[], resetKey: string, initial = 25) {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(() => { try { const v = Number(localStorage.getItem('smw_k8s_page')); return PAGE_SIZES.includes(v) ? v : initial; } catch { return initial; } });
  useEffect(() => setPage(0), [resetKey, size]);
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const current = Math.min(page, pages - 1);
  const chooseSize = (n: number) => { setSize(n); try { localStorage.setItem('smw_k8s_page', String(n)); } catch { /* ignore */ } };
  return { rows: rows.slice(current * size, current * size + size), pager: <Pager page={current} pages={pages} size={size} total={rows.length} onPage={setPage} onSize={chooseSize} /> };
}

/* ---------------------------------------------------------------- side panels: any object with what is related to it */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Obj = { [key: string]: any };
type SvcRow = { ns: string; name: string; type: string; cluster_ip: string; external: string[]; ports: string[]; selector?: Record<string, string> };
type Link = { kind: string; name: string; ns: string; relation?: string };
type Related = { object: Obj; events: Ev[]; pods?: Pod[]; services?: SvcRow[]; links?: Link[]; selector?: string };
export type Target = { resource: string; ns: string; name: string };
const RESOURCE_OF: Record<string, string> = { Pod: 'pod', Deployment: 'deployment', StatefulSet: 'statefulset', DaemonSet: 'daemonset', Job: 'job', CronJob: 'cronjob', Service: 'service', Ingress: 'ingress',
  PersistentVolumeClaim: 'pvc', HorizontalPodAutoscaler: 'hpa', Node: 'node', Namespace: 'namespace' };
const LABEL_OF: Record<string, string> = { pod: 'Pod', deployment: 'Deployment', statefulset: 'StatefulSet', daemonset: 'DaemonSet', job: 'Job', cronjob: 'CronJob', service: 'Service', ingress: 'Ingress', pvc: 'Volume claim', hpa: 'Autoscaler', node: 'Node', namespace: 'Namespace' };

/** Asks the agent for an object plus everything related to it. Agents older than 1.2 only know `describe`: then the panel shows the
 *  object and its events, and says what the update would add. */
function useRelated(cluster: Cluster, target: Target) {
  const [legacy, setLegacy] = useState(false);
  const r = useCluster<Related>(cluster.id, { kind: legacy ? 'describe' : 'related', resource: target.resource, namespace: target.ns, name: target.name }, [target.resource, target.ns, target.name, legacy], 1);
  useEffect(() => { if (!legacy && /unknown query kind/i.test(r.error)) setLegacy(true); }, [r.error, legacy]);
  return { ...r, legacy };
}

function EventList({ events, empty }: { events: Ev[]; empty: string }) {
  const [all, setAll] = useState(false);
  if (!events.length) return <p className="muted sm">{empty}</p>;
  return <>{(all ? events : events.slice(0, 10)).map((e, i) => (
    <div key={i} className="evt"><span className={`evt-dot ${e.type === 'Warning' ? 'warn' : ''}`} /><div><b className={e.type === 'Warning' ? 'warn' : ''}>{e.reason}</b> <span className="muted sm">{e.object ? `${e.object} · ` : ''}{timeAgo(e.last)}{e.count > 1 ? ` ×${e.count}` : ''}</span><div className="sm">{e.message}</div></div></div>))}
    {events.length > 10 && <button className="ssh-more" onClick={() => setAll(!all)}>{all ? 'See less' : `See all ${events.length} events`}</button>}</>;
}

/** Pods, services and linked objects of a panel. Every row opens its own panel. */
function RelatedBlock({ data, open, self }: { data: Related; open: (t: Target) => void; self: Target }) {
  const pods = data.pods ?? [];
  const paged = usePaged(pods, `${self.resource}/${self.ns}/${self.name}`, 10);
  const links = (data.links ?? []).filter(l => l.name);
  return <>
    {links.length > 0 && <><h3 className="drawer-h">Connected to</h3><div className="rel-links">
      {links.map((l, i) => { const res = RESOURCE_OF[l.kind]; return res
        ? <button key={i} type="button" className="rel-link" onClick={() => open({ resource: res, ns: l.ns, name: l.name })}><small>{l.relation ?? l.kind}</small><b>{l.kind}</b> {l.name}</button>
        : <span key={i} className="rel-link static"><small>{l.relation ?? l.kind}</small><b>{l.kind}</b> {l.name}</span>; })}
    </div></>}
    {self.resource !== 'pod' && data.pods && <><h3 className="drawer-h">Pods <span className="tag">{pods.length}</span>{data.selector ? <span className="muted mono sm" style={{ textTransform: 'none', letterSpacing: 0, marginLeft: 8 }}>{data.selector}</span> : null}</h3>
      {pods.length === 0 ? <p className="muted sm">No pods {self.resource === 'pvc' ? 'use this claim' : 'match'}.</p> : <>
        <table className="tbl ktbl"><thead><tr><th>Pod</th><th>Status</th><th>Ready</th><th className="num">Restarts</th><th className="hide-sm">Node</th></tr></thead><tbody>
          {paged.rows.map(p => <tr key={p.name} className="click" onClick={() => open({ resource: 'pod', ns: p.ns, name: p.name })}><td className="trunc" style={{ maxWidth: 220 }} title={p.name}><b>{p.name}</b></td>
            <td><span className={`kstatus ${podTone(p.status)}`}><i />{p.status}</span></td><td className="sm">{p.ready}</td><td className="num">{p.restarts || <span className="muted">0</span>}</td><td className="sm hide-sm trunc" style={{ maxWidth: 120 }}>{p.node}</td></tr>)}
        </tbody></table>{paged.pager}</>}</>}
    {(data.services ?? []).length > 0 && <><h3 className="drawer-h">Services sending traffic here</h3>
      {(data.services ?? []).map(s => <button key={s.name} type="button" className="rel-row" onClick={() => open({ resource: 'service', ns: s.ns, name: s.name })}><b>{s.name}</b><span className="muted sm">{s.type} · {s.cluster_ip || 'no IP'}</span><span className="mono sm">{s.ports.join(', ')}</span></button>)}</>}
  </>;
}

const cond = (o: Obj) => ((o.status?.conditions ?? []) as { type: string; status: string; reason?: string; message?: string }[]);
const fmtSel = (sel?: Record<string, string>) => (sel && Object.keys(sel).length ? Object.entries(sel).map(([k, v]) => `${k}=${v}`).join(', ') : '–');
/** The few facts that matter for each kind of object, in plain words. */
function factsFor(resource: string, o: Obj): [string, ReactNode][] {
  const spec = o.spec ?? {}, st = o.status ?? {};
  const images = (spec.template?.spec?.containers ?? spec.jobTemplate?.spec?.template?.spec?.containers ?? []).map((c: Obj) => c.image).join(', ') || '–';
  const created: [string, ReactNode] = ['Created', o.metadata?.creationTimestamp ? timeAgo(o.metadata.creationTimestamp) : '–'];
  switch (resource) {
    case 'deployment': return [['Replicas', `${st.readyReplicas ?? 0} ready / ${spec.replicas ?? 0} wanted`], ['Up to date', st.updatedReplicas ?? 0], ['Available', st.availableReplicas ?? 0], ['Strategy', spec.strategy?.type ?? '–'], ['Revision', o.metadata?.annotations?.['deployment.kubernetes.io/revision'] ?? '–'], created, ['Images', <span className="mono" key="i">{images}</span>]];
    case 'statefulset': return [['Replicas', `${st.readyReplicas ?? 0} ready / ${spec.replicas ?? 0} wanted`], ['Service', spec.serviceName ?? '–'], ['Update strategy', spec.updateStrategy?.type ?? '–'], ['Volume templates', (spec.volumeClaimTemplates ?? []).map((v: Obj) => v.metadata?.name).join(', ') || '–'], created, ['Images', <span className="mono" key="i">{images}</span>]];
    case 'daemonset': return [['Scheduled', `${st.currentNumberScheduled ?? 0} / ${st.desiredNumberScheduled ?? 0} nodes`], ['Ready', st.numberReady ?? 0], ['Unavailable', st.numberUnavailable ?? 0], ['Misscheduled', st.numberMisscheduled ?? 0], created, ['Images', <span className="mono" key="i">{images}</span>]];
    case 'job': return [['Succeeded', `${st.succeeded ?? 0}${spec.completions ? ` / ${spec.completions}` : ''}`], ['Failed', st.failed ?? 0], ['Active', st.active ?? 0], ['Started', st.startTime ? timeAgo(st.startTime) : '–'], ['Finished', st.completionTime ? timeAgo(st.completionTime) : '–'], ['Images', <span className="mono" key="i">{images}</span>]];
    case 'cronjob': return [['Schedule', <span className="mono" key="s">{spec.schedule}</span>], ['Suspended', spec.suspend ? 'yes' : 'no'], ['Last run', st.lastScheduleTime ? timeAgo(st.lastScheduleTime) : 'never'], ['Last success', st.lastSuccessfulTime ? timeAgo(st.lastSuccessfulTime) : '–'], ['Running now', (st.active ?? []).length], ['Images', <span className="mono" key="i">{images}</span>]];
    case 'service': return [['Type', spec.type ?? 'ClusterIP'], ['Cluster IP', <span className="mono" key="c">{spec.clusterIP ?? '–'}</span>], ['External', <span className="mono" key="e">{[...((st.loadBalancer?.ingress ?? []).map((i: Obj) => i.ip || i.hostname)), ...(spec.externalIPs ?? [])].join(', ') || '–'}</span>],
      ['Ports', <span className="mono" key="p">{(spec.ports ?? []).map((p: Obj) => `${p.name ? `${p.name} ` : ''}${p.port}→${p.targetPort ?? p.port}/${p.protocol ?? 'TCP'}${p.nodePort ? ` (node ${p.nodePort})` : ''}`).join(', ') || '–'}</span>], ['Selector', <span className="mono" key="s">{fmtSel(spec.selector)}</span>], ['Session affinity', spec.sessionAffinity ?? '–'], created];
    case 'ingress': return [['Class', spec.ingressClassName ?? '–'], ['Hosts', (spec.rules ?? []).map((r: Obj) => r.host ?? '*').join(', ') || '–'], ['TLS', (spec.tls ?? []).flatMap((t: Obj) => t.hosts ?? []).join(', ') || 'none'], ['Address', (st.loadBalancer?.ingress ?? []).map((i: Obj) => i.ip || i.hostname).join(', ') || '–'], created];
    case 'pvc': return [['Status', st.phase ?? '–'], ['Capacity', st.capacity?.storage ?? spec.resources?.requests?.storage ?? '–'], ['Storage class', spec.storageClassName ?? '–'], ['Access', (spec.accessModes ?? []).join(', ') || '–'], ['Volume', <span className="mono" key="v">{spec.volumeName ?? '–'}</span>], created];
    case 'hpa': return [['Replicas', `${st.currentReplicas ?? 0} now · wants ${st.desiredReplicas ?? 0} · ${spec.minReplicas ?? 1}–${spec.maxReplicas}`], ['Target', `${spec.scaleTargetRef?.kind}/${spec.scaleTargetRef?.name}`], ['Last scaled', st.lastScaleTime ? timeAgo(st.lastScaleTime) : '–'], created];
    case 'node': return [['Kubelet', st.nodeInfo?.kubeletVersion ?? '–'], ['OS', st.nodeInfo?.osImage ?? '–'], ['Runtime', st.nodeInfo?.containerRuntimeVersion ?? '–'], ['CPU', st.allocatable?.cpu ?? '–'], ['Memory', st.allocatable?.memory ?? '–'], ['Pods', st.allocatable?.pods ?? '–'], ['Address', (st.addresses ?? []).map((a: Obj) => a.address).join(', ')], ['Unschedulable', spec.unschedulable ? 'yes (cordoned)' : 'no']];
    default: return [created];
  }
}

function ResourceDrawer({ cluster, target, onClose, onBack, open }: { cluster: Cluster; target: Target; onClose: () => void; onBack?: () => void; open: (t: Target) => void }) {
  const d = useRelated(cluster, target);
  const { toast } = useApp();
  const [showObject, setShowObject] = useState(false);
  const o = d.data?.data?.object;
  const problems = o ? cond(o).filter(c => (['Ready', 'Available', 'Progressing', 'Complete'].includes(c.type) ? c.status === 'False' : ['Failed', 'ReplicaFailure', 'MemoryPressure', 'DiskPressure', 'PIDPressure', 'NetworkUnavailable'].includes(c.type) && c.status === 'True')) : [];
  return (
    <aside className="drawer" role="dialog" aria-modal="true" aria-label={`${LABEL_OF[target.resource]} ${target.name}`}>
      <div className="drawer-head">
        {onBack && <button className="btn ghost sm" onClick={onBack} aria-label="Back"><Icon name="back" size={15} /></button>}
        <div style={{ minWidth: 0 }}><div className="sm muted">{LABEL_OF[target.resource] ?? target.resource}{target.ns && <> · <span className="nschip">{target.ns}</span></>}</div><h2 className="trunc" title={target.name}>{target.name}</h2></div>
        <span className="grow" /><button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
      </div>
      <div className="drawer-actions">
        {problems.length ? <span className="kstatus bad"><i />{problems.map(c => c.type).join(', ')}</span> : o ? <span className="kstatus ok"><i />Healthy</span> : null}
        <button className="btn sm" onClick={() => { void navigator.clipboard?.writeText(`kubectl${target.ns ? ` -n ${target.ns}` : ''} describe ${target.resource === 'pvc' ? 'pvc' : target.resource} ${target.name}`); toast('kubectl command copied'); }}>Copy kubectl describe</button>
      </div>
      <div className="drawer-body">
        <Loading busy={d.busy && !d.data} error={d.legacy ? '' : d.error} retry={d.reload} />
        {d.legacy && <p className="sm warn">The cluster agent is older than 1.2, so related pods and services are not shown. Update it from the cluster&apos;s Overview.</p>}
        {o && <>
          <div className="facts">{factsFor(target.resource, o).map(([k, v]) => <div key={k}><small>{k}</small><b>{v}</b></div>)}</div>
          {problems.length > 0 && <><h3 className="drawer-h">Problems</h3>{problems.map(c => <div key={c.type} className="sm" style={{ marginBottom: 6 }}><b className="bad">{c.type}</b> {c.reason}{c.message ? `: ${c.message}` : ''}</div>)}</>}
          <RelatedBlock data={d.data!.data!} open={open} self={target} />
          <h3 className="drawer-h">Events</h3>
          <EventList events={d.data?.data?.events ?? []} empty={target.resource === 'pod' ? 'No events for this pod.' : 'No events for this object or its pods (Kubernetes keeps events for about an hour).'} />
          {o.metadata?.labels && Object.keys(o.metadata.labels).length > 0 && <><h3 className="drawer-h">Labels</h3><div className="chips">{Object.entries(o.metadata.labels as Record<string, string>).slice(0, 16).map(([k, v]) => <span key={k} className="chip mono" title={`${k}=${v}`}>{k.split('/').pop()}={v.length > 24 ? `${v.slice(0, 22)}…` : v}</span>)}</div></>}
          <div style={{ marginTop: 14 }}><button className="btn sm" onClick={() => setShowObject(!showObject)}>{showObject ? 'Hide' : 'Show'} full object (secret values removed)</button></div>
          {showObject && <pre className="codebox" style={{ maxHeight: 420, overflow: 'auto', whiteSpace: 'pre-wrap', marginTop: 8 }}>{JSON.stringify(o, null, 2)}</pre>}
        </>}
      </div>
    </aside>
  );
}

/* ---------------------------------------------------------------- pod logs */
const POD_DOT = (status: string) => (/^Running$|^Completed$|^Succeeded$/.test(status) ? (status === 'Running' ? 'running' : '') : /Pending|Init|Creating|Terminating|Containers/i.test(status) ? 'paused' : 'exited');

function PodLogs({ cluster, preset }: { cluster: Cluster; preset?: { ns: string; pod: string } | null }) {
  const [ns, setNs] = useState(preset?.ns ?? '');
  const [pod, setPod] = useState(preset?.pod ?? '');
  const [container, setContainer] = useState('');
  const [previous, setPrevious] = useState(false);
  const pods = useCluster<Items<Pod>>(cluster.id, ns ? { kind: 'pods', namespace: ns, limit: 500 } : null, [ns]);
  const nsList = useCluster<Items<{ name: string }>>(cluster.id, { kind: 'namespaces' }, []);
  const allowed = (n: string) => cluster.log_policy.enabled && cluster.log_policy.include.some(p => glob(p, n)) && !cluster.log_policy.exclude.some(p => glob(p, n));
  const nsOptions = (nsList.data?.data?.items ?? []).filter(n => allowed(n.name)).map(n => ({ value: n.name, label: n.name }));
  const hidden = (nsList.data?.data?.items ?? []).length - nsOptions.length;
  const podItems = pods.data?.data?.items ?? [];
  const podOptions = podItems.map(p => ({ value: p.name, label: p.name, dot: POD_DOT(p.status), hint: p.status === 'Running' ? undefined : p.status }));
  const podRow = podItems.find(p => p.name === pod);
  useEffect(() => { setContainer(''); }, [pod]);

  const fetcher: LogFetch = useCallback(async (q, cancelled) => {
    const r = await ask<never>(cluster.id, { kind: 'logs', namespace: ns, name: pod, container, previous, lines: q.lines, since_seconds: q.sinceSeconds, grep: q.grep }, cancelled);
    return { text: r.text ?? '', truncated: r.truncated };
  }, [cluster.id, ns, pod, container, previous]);

  const controls = (
    <>
      <TargetPicker value={ns} options={nsOptions} onChange={v => { setNs(v); setPod(''); }} icon="k8s" placeholder="Namespace…" width={220} />
      <TargetPicker value={pod} options={podOptions} onChange={setPod} icon="server" placeholder={ns ? (pods.busy ? 'Loading pods…' : 'Choose a pod…') : 'Choose a pod'} disabled={!ns} width={360} />
      {podRow && podRow.containers.length > 1 && <select className="lg-mini" style={{ height: 38 }} value={container} onChange={e => setContainer(e.target.value)} aria-label="Container"><option value="">All containers</option>{podRow.containers.map(c => <option key={c.name} value={c.name}>{c.name}</option>)}</select>}
      <label className="lg-opt"><input type="checkbox" checked={previous} onChange={e => setPrevious(e.target.checked)} />Previous (crashed) container</label>
      {hidden > 0 && <span className="sm muted" title="An admin limited which namespaces' logs can be read (Settings tab)"><Icon name="shield" size={13} /> {hidden} namespace{hidden === 1 ? '' : 's'} hidden by policy</span>}
    </>
  );
  const banner = cluster.restricted ? <div className="lv-note"><p><Icon name="shield" size={14} />Log access is limited by this cluster’s policy ({cluster.log_policy.enabled ? `only ${cluster.log_policy.include.join(', ')}${cluster.log_policy.exclude.length ? `, not ${cluster.log_policy.exclude.join(', ')}` : ''}` : 'off'}). Every read is recorded in the audit log.</p></div> : null;
  return (
    <LogViewer fetcher={fetcher} fetchKey={`${cluster.id}|${ns}|${pod}|${container}|${previous}`} canFetch={!!ns && !!pod} controls={controls} banner={banner} storageKey={`cluster-${cluster.id}`} downloadName={pod || 'pod-logs'}
      emptyHint={!pod ? <p className="muted sm">Choose a namespace and a pod above. Logs are fetched when you ask and are never stored on the control plane.</p> : undefined} />
  );
}

/** Same matching rules as the control plane and the agent (* ? and [..]). */
function glob(pattern: string, value: string): boolean {
  const rx = '^' + pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
  try { return new RegExp(rx).test(value); } catch { return false; }
}

/* ---------------------------------------------------------------- settings */
function ClusterSettings({ cluster, isAdmin, reload }: { cluster: Cluster; isAdmin: boolean; reload: () => Promise<void> }) {
  const { toast, confirm } = useApp();
  const [name, setName] = useState(cluster.name);
  const [rotated, setRotated] = useState<string | null>(null);
  const [policy, setPolicy] = useState<K8sLogPolicy>(cluster.log_policy);
  const [include, setInclude] = useState(cluster.log_policy.include.join('\n'));
  const [exclude, setExclude] = useState(cluster.log_policy.exclude.join('\n'));
  const lines = (v: string) => v.split('\n').map(x => x.trim()).filter(Boolean);
  const [alerts, setAlerts] = useState<MonitorAlerts>(alertsOf(cluster));

  async function run(fn: () => Promise<unknown>, ok: string) { try { await fn(); toast(ok); await reload(); } catch (e) { toast((e as Error).message, true); } }
  async function revokeNow() {
    if (!(await confirm('Revoke the agent token NOW?\n\nThe agent goes offline until you patch the new token into its Secret.'))) return;
    try { setRotated((await post<{ install_token: string }>(`/clusters/${cluster.id}/rotate-token?immediate=true`)).install_token); await reload(); } catch (e) { toast((e as Error).message, true); }
  }
  return (
    <div className="grid g2">
      <section className="card"><div className="card-head"><h2>Cluster</h2></div>
        <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} maxLength={60} /></Field>
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          <button className="btn primary sm" disabled={name === cluster.name} onClick={() => void run(() => put(`/clusters/${cluster.id}`, { name }), 'Renamed')}>Save name</button>
          <button className="btn sm" onClick={() => void run(() => put(`/clusters/${cluster.id}`, { enabled: !cluster.enabled }), cluster.enabled ? 'Disabled' : 'Enabled')}>{cluster.enabled ? 'Disable monitoring' : 'Enable monitoring'}</button>
        </div>
        <table className="tbl" style={{ marginTop: 12 }}><tbody>
          <tr><td className="muted">Agent token</td><td>{cluster.token_issued_at ? `issued ${timeAgo(cluster.token_issued_at)}` : '–'}{cluster.token_rotation_pending && <> · <span className="warn">rotation pending</span></>}</td></tr>
          {cluster.last_agent_ip && <tr><td className="muted">Last seen from</td><td className="mono">{cluster.last_agent_ip}</td></tr>}
          <tr><td className="muted">Registered by</td><td className="sm">{cluster.created_by || '–'}</td></tr></tbody></table>
        <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
          <button className="btn sm" disabled={cluster.token_rotation_pending} onClick={async () => { if (await confirm('Rotate the agent token?\n\nThe new token is delivered to the agent automatically and saved to its Secret. Nothing needs to be reinstalled.', { danger: false, confirmLabel: 'Rotate token' })) void run(() => post(`/clusters/${cluster.id}/rotate-token`), 'Token rotation started'); }}>{cluster.token_rotation_pending ? 'Rotation pending…' : 'Rotate token'}</button>
          <button className="btn sm danger" onClick={revokeNow}>Revoke now</button>
        </div>
      </section>
      <section className="card"><div className="card-head"><h2>Pod log access</h2></div>
        <p className="sm muted">Which namespaces’ pod logs operators may read. Enforced by the control plane and by the in-cluster agent. Patterns: <code>*</code> <code>?</code>.</p>
        {!isAdmin && <p className="sm warn">Only admins can change this.</p>}
        <label className="check" style={{ margin: '8px 0' }}><input type="checkbox" disabled={!isAdmin} checked={policy.enabled} onChange={e => setPolicy({ ...policy, enabled: e.target.checked })} />Allow reading pod logs</label>
        <Field label="Allowed namespaces (one per line)"><textarea rows={3} disabled={!isAdmin || !policy.enabled} value={include} onChange={e => setInclude(e.target.value)} /></Field>
        <Field label="Never allow (one per line)" hint="e.g. kube-system, smwatch, payments-*"><textarea rows={3} disabled={!isAdmin || !policy.enabled} value={exclude} onChange={e => setExclude(e.target.value)} /></Field>
        <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
          <button className="btn primary sm" disabled={!isAdmin} onClick={() => void run(() => put(`/clusters/${cluster.id}/log-policy`, { enabled: policy.enabled, include: lines(include), exclude: lines(exclude) }), 'Log policy saved')}>Save policy</button>
          <button className="btn sm" disabled={!isAdmin} onClick={() => { setPolicy({ enabled: true, include: ['*'], exclude: [] }); setInclude('*'); setExclude(''); }}>Reset to default</button>
        </div>
      </section>
      <section className="card" style={{ gridColumn: '1 / -1' }}>
        <div className="card-head"><h2>Alerts</h2></div>
        <MonitorAlertSettings kind="cluster" value={alerts} onChange={setAlerts} />
        <div style={{ marginTop: 12 }}><button className="btn primary sm" onClick={() => void run(() => put(`/clusters/${cluster.id}`, { alert_settings: true, ...alerts }), 'Alert settings saved')}>Save alert settings</button></div>
      </section>
      {rotated && <Modal title="New agent token" onClose={() => setRotated(null)}>
        <p className="sm">Shown once. Patch it into the agent’s Secret, then restart the pod:</p>
        <CodeBox value={`kubectl -n smwatch patch secret smwatch-agent --type merge -p '{"stringData":{"token":"${rotated}"}}' && kubectl -n smwatch rollout restart deploy/smwatch-agent`} />
      </Modal>}
    </div>
  );
}
