'use client';

import { FormEvent, ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { AreaChart } from '../components/charts';
import { ClusterAgentUpdate } from '../components/agentupdate';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { useActiveEnrollment, useControlPlaneUrl } from '../components/join';
import { Highlight, LEVEL_LABEL, parse } from '../components/logs';
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

/** Fetches a list from the cluster when mounted (and when `deps` change). Nothing is stored on the control plane. */
function useCluster<T>(clusterId: number, query: Record<string, unknown> | null, deps: unknown[], refreshMs = 0) {
  const [state, setState] = useState<{ data: Answer<T> | null; error: string; busy: boolean }>({ data: null, error: '', busy: false });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!query) return;
    let stop = false;
    setState(s => ({ ...s, busy: true }));
    ask<T>(clusterId, query, () => stop).then(data => !stop && setState({ data, error: '', busy: false }))
      .catch(e => !stop && (e as Error).message !== 'cancelled' && setState(s => ({ ...s, error: (e as Error).message, busy: false })));
    return () => { stop = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterId, tick, ...deps]);
  useEffect(() => {
    if (!refreshMs) return;
    const t = window.setInterval(() => { if (!document.hidden) setTick(n => n + 1); }, refreshMs);
    return () => window.clearInterval(t);
  }, [refreshMs]);
  return { ...state, reload: () => setTick(n => n + 1) };
}

type Items<R> = { items: R[]; truncated: boolean };

/* ---------------------------------------------------------------- routing */
export function Kubernetes() {
  const lim = useLimits();
  const { route, go, canOperate } = useApp();
  const { value: clusters, reload } = usePoll(() => api<Cluster[]>('/clusters'), [], 10000);
  if (!clusters) return <p className="muted">Loading…</p>;
  if (route[1] && route[1] !== 'new') {
    const cluster = clusters.find(c => c.id === Number(route[1]));
    return cluster ? <ClusterDetail cluster={cluster} reload={reload} /> : <Empty title="Cluster not found" action={<button className="btn" onClick={() => go('kubernetes')}>Back to clusters</button>} />;
  }
  return (
    <>
      <div className="topbar"><h1>Kubernetes</h1><span className="grow" />{canOperate && <button className="btn primary" onClick={() => go('kubernetes/new')}><Icon name="plus" size={15} />Add cluster</button>}</div>
      {clusters.length === 0 ? (
        <div className="card"><Empty title="No clusters yet" action={canOperate ? <button className="btn primary" onClick={() => go('kubernetes/new')}>Connect your first cluster</button> : undefined}>
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
      {route[1] === 'new' && canOperate && <AddCluster onClose={() => { go('kubernetes'); void reload(); }} />}
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
type TabId = 'overview' | 'workloads' | 'pods' | 'nodes' | 'scaling' | 'network' | 'events' | 'logs' | 'settings';

function ClusterDetail({ cluster, reload }: { cluster: Cluster; reload: () => Promise<void> }) {
  const lim = useLimits();
  const { go, toast, canOperate, isAdmin, confirm } = useApp();
  const [tab, setTab] = useState<TabId>('overview');
  const tabs: [TabId, string][] = [['overview', 'Overview'], ['workloads', 'Workloads'], ['pods', 'Pods'], ['nodes', 'Nodes'], ['scaling', 'Autoscaling'], ['network', 'Network & storage'], ['events', 'Events']];
  if (canOperate) tabs.push(['logs', 'Logs'], ['settings', 'Settings']);
  const offline = !cluster.last_seen_at || Date.now() - new Date(cluster.last_seen_at).getTime() > lim.offlineMs;

  async function remove() {
    if (!(await confirm(`Remove ${cluster.name}?\n\nIts history is deleted from SM-Watch. The agent inside the cluster is not uninstalled: delete the 'smwatch' namespace there.`))) return;
    try { await del(`/clusters/${cluster.id}`); toast('Cluster removed'); go('kubernetes'); } catch (e) { toast((e as Error).message, true); }
  }
  return (
    <>
      <div className="topbar">
        <button className="btn ghost sm" onClick={() => go('kubernetes')}><Icon name="back" size={15} />Clusters</button>
        <h1>{cluster.name}</h1><StatusPill status={cluster.status} /><span className="tag">{cluster.k8s_version || 'unknown version'}</span>
        <span className="grow" />
        <span className="sm muted">agent {cluster.agent_version ? `v${cluster.agent_version}` : '–'} · seen {timeAgo(cluster.last_seen_at)}</span>
        {canOperate && <button className="btn sm danger" onClick={remove}>Remove</button>}
      </div>
      <div className="tabs" role="tablist">{tabs.map(([id, label]) => <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>{label}</button>)}</div>
      {cluster.agent_outdated && cluster.latest_agent_version && <div style={{ marginBottom: 16 }}><ClusterAgentUpdate current={cluster.agent_version} latest={cluster.latest_agent_version} /></div>}
      {cluster.status !== 'up' && cluster.last_error && <div className="err" style={{ marginBottom: 16 }}>{cluster.last_error}</div>}
      {offline && tab !== 'overview' && tab !== 'settings' ? <div className="card"><Empty title="The cluster agent is offline">It has not reported for over 2 minutes, so live data cannot be fetched. Check the <code>smwatch-agent</code> pod in the <code>smwatch</code> namespace.</Empty></div> : (
        <>
          {tab === 'overview' && <Overview cluster={cluster} />}
          {tab === 'workloads' && <Workloads cluster={cluster} />}
          {tab === 'pods' && <Pods cluster={cluster} />}
          {tab === 'nodes' && <Nodes cluster={cluster} />}
          {tab === 'scaling' && <Scaling cluster={cluster} />}
          {tab === 'network' && <Network cluster={cluster} />}
          {tab === 'events' && <Events cluster={cluster} />}
          {tab === 'logs' && canOperate && <PodLogs cluster={cluster} />}
          {tab === 'settings' && canOperate && <ClusterSettings cluster={cluster} isAdmin={isAdmin} reload={reload} />}
        </>
      )}
    </>
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

function TopList({ title, rows, format, color, hint }: { title: string; rows: { name: string; sub: string; value: number }[]; format: (v: number) => string; color: string; hint?: string }) {
  const max = Math.max(1, ...rows.map(r => r.value));
  return (
    <section className="card">
      <div className="card-head"><h2>{title}</h2>{hint && <><span className="grow" /><span className="sm muted">{hint}</span></>}</div>
      {rows.length === 0 ? <p className="muted sm">No data.</p> : <div className="toplist">{rows.map(r => (
        <div key={r.sub + r.name} className="toprow">
          <div className="toprow-name" title={`${r.sub}/${r.name}`}><b>{r.name}</b><small>{r.sub}</small></div>
          <div className="toprow-bar"><i style={{ width: `${(r.value / max) * 100}%`, background: color }} /></div>
          <span className="toprow-val">{format(r.value)}</span>
        </div>))}</div>}
    </section>
  );
}

function Overview({ cluster }: { cluster: Cluster }) {
  const lim = useLimits();
  const s = cluster.summary;
  const hist = usePoll(() => api<{ points: Point[]; samples: number }>(`/clusters/${cluster.id}/history?range=24h`), [cluster.id], 30000);
  const online = !!cluster.last_seen_at && Date.now() - new Date(cluster.last_seen_at).getTime() < lim.offlineMs;
  const pods = useCluster<Items<Pod>>(online && s ? cluster.id : 0, online && s ? { kind: 'pods', limit: 500 } : null, [], 30000);
  const podUse = useCluster<Items<PodUsage> & { available: boolean }>(online && s ? cluster.id : 0, online && s ? { kind: 'pod_metrics' } : null, [], 30000);
  const nodes = useCluster<Items<NodeRow>>(online && s ? cluster.id : 0, online && s ? { kind: 'nodes' } : null, [], 30000);
  const nodeUse = useCluster<Items<{ name: string; cpu_m: number; mem_mib: number }> & { available: boolean }>(online && s ? cluster.id : 0, online && s ? { kind: 'node_metrics' } : null, [], 30000);
  const events = useCluster<Items<Ev>>(online && s ? cluster.id : 0, online && s ? { kind: 'events', warnings_only: true, limit: 8 } : null, [], 30000);
  if (!s) return <div className="card"><Empty title="Waiting for the agent">No report has been received yet. Run the install command on a machine with kubectl access.</Empty></div>;

  const cpuPct = s.cpu_m != null && s.cpu_alloc_m ? (s.cpu_m / s.cpu_alloc_m) * 100 : null;
  const memPct = s.mem_mib != null && s.mem_alloc_mib ? (s.mem_mib / s.mem_alloc_mib) * 100 : null;
  const failing = s.pods_crashloop + s.pods_failed;
  const workloads = s.deployments_total + s.statefulsets_total + s.daemonsets_total;
  const unavailable = s.deployments_unavailable + s.statefulsets_unavailable + s.daemonsets_unavailable;
  const issues = s.problems.length;
  const points = hist.value?.points ?? [];

  const podList = pods.data?.data?.items ?? [];
  const usage = new Map((podUse.data?.data?.items ?? []).map(x => [`${x.ns}/${x.name}`, x]));
  const topCpu = [...(podUse.data?.data?.items ?? [])].sort((a, b) => b.cpu_m - a.cpu_m).slice(0, 7).map(x => ({ name: x.name, sub: x.ns, value: x.cpu_m }));
  const topMem = [...(podUse.data?.data?.items ?? [])].sort((a, b) => b.mem_mib - a.mem_mib).slice(0, 7).map(x => ({ name: x.name, sub: x.ns, value: x.mem_mib }));
  const topRestarts = [...podList].filter(p => p.restarts > 0).sort((a, b) => b.restarts - a.restarts).slice(0, 7).map(p => ({ name: p.name, sub: p.ns, value: p.restarts }));
  const byNs = new Map<string, { pods: number; mem: number; cpu: number }>();
  for (const p of podList) { const r = byNs.get(p.ns) ?? { pods: 0, mem: 0, cpu: 0 }; const u = usage.get(`${p.ns}/${p.name}`); r.pods++; r.mem += u?.mem_mib ?? 0; r.cpu += u?.cpu_m ?? 0; byNs.set(p.ns, r); }
  const topNs = [...byNs.entries()].sort((a, b) => (b[1].mem || b[1].pods) - (a[1].mem || a[1].pods)).slice(0, 7).map(([name, r]) => ({ name, sub: `${r.pods} pods`, value: r.mem || r.pods }));
  const nsUsesMem = [...byNs.values()].some(r => r.mem > 0);
  const noReq = podList.filter(p => p.status === 'Running' && !p.cpu_req_m && !p.mem_req_mib && !p.ns.startsWith('kube-')).length;
  const noLimit = podList.filter(p => p.status === 'Running' && !p.mem_lim_mib && !p.ns.startsWith('kube-')).length;

  return (
    <div className="grid">
      <section className={`khero ${cluster.status}`}>
        <span className="khero-ico"><Icon name={cluster.status === 'up' ? 'check' : 'alert'} size={22} /></span>
        <div style={{ minWidth: 0 }}>
          <div className="khero-title">{cluster.status === 'up' ? 'All systems healthy' : issues ? `${issues} issue${issues === 1 ? '' : 's'} need attention` : cluster.status === 'down' ? 'Agent is not reporting' : 'Degraded'}</div>
          <div className="khero-sub">{s.nodes_ready}/{s.nodes_total} nodes ready · {s.pods_running}/{s.pods_total} pods running · {workloads} workloads · {s.namespaces} namespaces · Kubernetes {cluster.k8s_version}</div>
        </div>
      </section>
      {s.problems.length > 0 && <section className="card" style={{ borderColor: 'color-mix(in srgb, var(--warn) 45%, var(--line))' }}><div className="card-head"><h2>Needs attention</h2></div><ul className="problems">{s.problems.map((p, i) => <li key={i}>{p}</li>)}</ul></section>}

      <div className="kpis">
        <Kpi icon="server" label="Nodes" value={<>{s.nodes_ready}<small>/{s.nodes_total}</small></>} tone={s.nodes_ready < s.nodes_total ? 'bad' : 'good'} sub={s.not_ready_nodes.length ? `not ready: ${s.not_ready_nodes.join(', ')}` : 'all ready'} />
        <Kpi icon="k8s" label="Pods" value={<>{s.pods_running}<small>/{s.pods_total}</small></>} tone={failing ? 'bad' : s.pods_pending ? 'warn' : 'good'} sub={`${s.pods_pending} pending · ${failing} failing · ${s.pods_succeeded} done`} />
        <Kpi icon="overview" label="CPU" value={cpuPct != null ? pct(cpuPct, 0) : '–'} tone={cpuPct != null ? level(cpuPct, lim.warn, lim.bad) : undefined} sub={s.cpu_m != null ? `${cores(s.cpu_m)} of ${cores(s.cpu_alloc_m ?? 0)}` : 'metrics-server not installed'}>{cpuPct != null && <Meter value={cpuPct} warnAt={lim.warn} badAt={lim.bad} />}</Kpi>
        <Kpi icon="logs" label="Memory" value={memPct != null ? pct(memPct, 0) : '–'} tone={memPct != null ? level(memPct, lim.warn, lim.bad) : undefined} sub={s.mem_mib != null ? `${mib(s.mem_mib)} of ${mib(s.mem_alloc_mib ?? 0)}` : 'metrics-server not installed'}>{memPct != null && <Meter value={memPct} warnAt={lim.warn} badAt={lim.bad} />}</Kpi>
        <Kpi icon="alert" label="Restarts" value={s.restarts.toLocaleString()} tone={s.pods_crashloop ? 'bad' : undefined} sub={`${s.pods_crashloop} crash-looping now`} />
        <Kpi icon="globe" label="Workloads" value={workloads} tone={unavailable ? 'bad' : 'good'} sub={`${s.deployments_total} deploy · ${s.statefulsets_total} sts · ${s.daemonsets_total} ds · ${s.hpa_total} HPA`} />
      </div>

      <div className="grid g2">
        <section className="card"><div className="card-head"><h2>Pod status</h2></div>
          <StackBar parts={[{ label: 'Running', value: s.pods_running, color: 'var(--good)' }, { label: 'Pending', value: s.pods_pending, color: 'var(--warn)' }, { label: 'Failed', value: s.pods_failed, color: 'var(--bad)' }, { label: 'Completed', value: s.pods_succeeded, color: 'var(--info)' }]} />
          {pods.data && <div className="chips" style={{ marginTop: 14 }}>
            <span className={`chip ${noReq ? 'warn' : ''}`} title="Running pods with neither CPU nor memory requests">{noReq} without requests</span>
            <span className={`chip ${noLimit ? 'warn' : ''}`} title="Running pods without a memory limit">{noLimit} without memory limit</span>
            {s.pods_truncated && <span className="chip warn">large cluster: partial list</span>}
          </div>}
        </section>
        <section className="card"><div className="card-head"><h2>Workload health</h2></div>
          {[['Deployments', s.deployments_total, s.deployments_unavailable], ['StatefulSets', s.statefulsets_total, s.statefulsets_unavailable], ['DaemonSets', s.daemonsets_total, s.daemonsets_unavailable]].map(([name, total, bad]) => (
            <div key={name as string} className="hrow"><span>{name}</span><span className="grow" /><b className={(bad as number) ? 'bad' : 'good'}>{(total as number) - (bad as number)}/{total as number}</b><span className="sm muted">available</span></div>))}
          <div className="hrow"><span>Autoscalers (HPA)</span><span className="grow" /><b>{s.hpa_total}</b></div>
        </section>
      </div>

      <div className="grid g2">
        <section className="card"><div className="card-head"><h2>CPU, last 24 h</h2><span className="grow" />{s.cpu_m != null && <span className="sm muted">now {cores(s.cpu_m)}</span>}</div>
          <AreaChart points={points} height={150} series={[{ key: 'cpu_m', label: 'Used', color: 'var(--c1)', format: v => cores(v) }]} />
          {s.cpu_alloc_m != null && <div className="sm muted" style={{ marginTop: 6 }}>Capacity {cores(s.cpu_alloc_m)}</div>}</section>
        <section className="card"><div className="card-head"><h2>Memory, last 24 h</h2><span className="grow" />{s.mem_mib != null && <span className="sm muted">now {mib(s.mem_mib)}</span>}</div>
          <AreaChart points={points} height={150} series={[{ key: 'mem_mib', label: 'Used', color: 'var(--c2)', format: v => mib(v) }]} />
          {s.mem_alloc_mib != null && <div className="sm muted" style={{ marginTop: 6 }}>Capacity {mib(s.mem_alloc_mib)}</div>}</section>
      </div>
      <section className="card"><div className="card-head"><h2>Pods over time</h2></div>
        <AreaChart points={points} height={130} series={[{ key: 'pods_running', label: 'Running', color: 'var(--good)' }, { key: 'pods_failing', label: 'Failing', color: 'var(--bad)' }]} /></section>

      {nodes.data && (nodes.data.data?.items ?? []).length > 0 && (
        <section className="card"><div className="card-head"><h2>Nodes</h2></div>
          <div className="nodegrid">{(nodes.data.data?.items ?? []).map(n => {
            const u = (nodeUse.data?.data?.items ?? []).find(x => x.name === n.name);
            const cp = u ? (u.cpu_m / n.cpu_alloc_m) * 100 : null, mp = u ? (u.mem_mib / n.mem_alloc_mib) * 100 : null;
            const issues = n.conditions.filter(c => (c.type === 'Ready' ? c.status !== 'True' : c.status === 'True'));
            const podsHere = podList.filter(p => p.node === n.name).length;
            return (
              <div key={n.name} className="nodecard">
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><b className="trunc" title={n.name}>{n.name}</b><span className="grow" /><StatusPill status={n.ready && !issues.length ? 'up' : 'alert'} label={n.ready ? (issues.length ? issues.map(i => i.type).join(', ') : 'Ready') : 'Not ready'} /></div>
                <div className="sm muted">{n.roles.join(', ')} · {n.version} · {n.ip}</div>
                <div className="nrow"><span>CPU</span>{cp != null ? <><Meter value={cp} warnAt={lim.warn} badAt={lim.bad} /><b>{pct(cp, 0)}</b></> : <span className="muted sm">{cores(n.cpu_alloc_m)}</span>}</div>
                <div className="nrow"><span>Memory</span>{mp != null ? <><Meter value={mp} warnAt={lim.warn} badAt={lim.bad} /><b>{pct(mp, 0)}</b></> : <span className="muted sm">{mib(n.mem_alloc_mib)}</span>}</div>
                <div className="nrow"><span>Pods</span><Meter value={(podsHere / Math.max(1, n.pods_cap)) * 100} warnAt={80} badAt={95} /><b>{podsHere}/{n.pods_cap}</b></div>
              </div>);
          })}</div>
        </section>)}

      <div className="grid g2">
        <TopList title="Top pods by CPU" rows={topCpu} format={cores} color="var(--c1)" hint={podUse.data?.data?.available === false ? 'needs metrics-server' : undefined} />
        <TopList title="Top pods by memory" rows={topMem} format={mib} color="var(--c2)" hint={podUse.data?.data?.available === false ? 'needs metrics-server' : undefined} />
        <TopList title={nsUsesMem ? 'Namespaces by memory' : 'Namespaces by pods'} rows={topNs} format={v => (nsUsesMem ? mib(v) : String(v))} color="var(--c4)" />
        <TopList title="Most restarts" rows={topRestarts} format={v => `${v}×`} color="var(--warn)" />
      </div>

      <section className="card"><div className="card-head"><h2>Recent warnings</h2></div>
        {!events.data ? <p className="muted sm">{events.error || 'Loading…'}</p> : (events.data.data?.items ?? []).length === 0 ? <p className="muted sm">No warning events. 🎉</p> : (
          <div className="tbl-wrap"><table className="tbl"><tbody>{(events.data.data?.items ?? []).map((e, i) => <tr key={i}><td className="sm" style={{ whiteSpace: 'nowrap' }}>{timeAgo(e.last)}{e.count > 1 && <small> ×{e.count}</small>}</td><td className="warn"><b>{e.reason}</b></td><td className="sm mono">{e.ns ? `${e.ns}/` : ''}{e.object}</td><td className="sm">{e.message}</td></tr>)}</tbody></table></div>)}
      </section>
    </div>
  );
}

type Workload = { ns: string; name: string; desired: number; ready: number; updated: number; images: string[]; message: string; kind?: string };
function Workloads({ cluster }: { cluster: Cluster }) {
  const [ns, setNs] = useState('');
  const dep = useCluster<Items<Workload>>(cluster.id, { kind: 'deployments', namespace: ns, limit: 500 }, [ns], 20000);
  const sts = useCluster<Items<Workload>>(cluster.id, { kind: 'statefulsets', namespace: ns, limit: 500 }, [ns], 20000);
  const dss = useCluster<Items<Workload>>(cluster.id, { kind: 'daemonsets', namespace: ns, limit: 500 }, [ns], 20000);
  const jobs = useCluster<Items<{ ns: string; name: string; state: string; succeeded: number; failed: number; completions: number | null; owner: string }>>(cluster.id, { kind: 'jobs', namespace: ns, limit: 200 }, [ns], 30000);
  const crons = useCluster<Items<{ ns: string; name: string; schedule: string; suspend: boolean; last: string | null; active: number }>>(cluster.id, { kind: 'cronjobs', namespace: ns, limit: 200 }, [ns], 30000);
  const rows = [...(dep.data?.data?.items ?? []).map(r => ({ ...r, kind: 'Deployment' })), ...(sts.data?.data?.items ?? []).map(r => ({ ...r, kind: 'StatefulSet' })), ...(dss.data?.data?.items ?? []).map(r => ({ ...r, kind: 'DaemonSet' }))];
  const [describe, setDescribe] = useState<{ resource: string; ns: string; name: string } | null>(null);
  return (
    <div className="grid">
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}><NamespaceSelect cluster={cluster} value={ns} onChange={setNs} /></div>
      <section className="card"><div className="card-head"><h2>Deployments, StatefulSets & DaemonSets</h2></div>
        <Loading busy={dep.busy && !dep.data} error={dep.error} retry={dep.reload} />
        {dep.data && (rows.length === 0 ? <p className="muted sm">None in this scope.</p> : (
          <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Kind</th><th>Ready</th><th>Up-to-date</th><th>Images</th></tr></thead><tbody>
            {rows.map(r => <tr key={`${r.kind}${r.ns}${r.name}`} className="click" onClick={() => setDescribe({ resource: r.kind!.toLowerCase(), ns: r.ns, name: r.name })}>
              <td><div className="name">{r.name}<small>{r.ns}</small></div></td><td className="sm">{r.kind}</td>
              <td className={r.ready < r.desired ? 'bad' : ''}><b>{r.ready}/{r.desired}</b></td><td>{r.updated}</td><td className="sm mono">{r.images.map(i => i.split('/').pop()).join(', ')}{r.message && <div className="bad sm">{r.message}</div>}</td></tr>)}
          </tbody></table></div>))}
        <Trunc on={dep.data?.data?.truncated} />
      </section>
      <section className="card"><div className="card-head"><h2>Jobs</h2></div>
        {jobs.data && ((jobs.data.data?.items ?? []).length === 0 ? <p className="muted sm">No jobs.</p> : <table className="tbl"><thead><tr><th>Name</th><th>State</th><th>Succeeded</th><th>Failed</th></tr></thead><tbody>
          {(jobs.data.data?.items ?? []).map(j => <tr key={j.ns + j.name}><td><div className="name">{j.name}<small>{j.ns}{j.owner ? ` · ${j.owner}` : ''}</small></div></td><td className={j.state === 'Failed' ? 'bad' : ''}>{j.state}</td><td>{j.succeeded}{j.completions ? `/${j.completions}` : ''}</td><td className={j.failed ? 'bad' : ''}>{j.failed}</td></tr>)}</tbody></table>)}
      </section>
      <section className="card"><div className="card-head"><h2>CronJobs</h2></div>
        {crons.data && ((crons.data.data?.items ?? []).length === 0 ? <p className="muted sm">No cron jobs.</p> : <table className="tbl"><thead><tr><th>Name</th><th>Schedule</th><th>Last run</th><th>Active</th></tr></thead><tbody>
          {(crons.data.data?.items ?? []).map(c => <tr key={c.ns + c.name}><td><div className="name">{c.name}<small>{c.ns}</small></div></td><td className="mono sm">{c.schedule}{c.suspend && <span className="tag">suspended</span>}</td><td>{timeAgo(c.last)}</td><td>{c.active}</td></tr>)}</tbody></table>)}
      </section>
      {describe && <Describe cluster={cluster} {...describe} onClose={() => setDescribe(null)} />}
    </div>
  );
}

type Pod = { ns: string; name: string; status: string; ready: string; restarts: number; node: string; ip: string; created: string | null; owner: string; qos: string;
  containers: { name: string; image: string; ready: boolean; restarts: number; state: string; reason: string }[]; cpu_req_m: number; mem_req_mib: number; cpu_lim_m: number; mem_lim_mib: number };
type PodUsage = { ns: string; name: string; cpu_m: number; mem_mib: number };
const badPod = (s: string) => /CrashLoop|Error|ImagePull|ErrImage|Failed|OOMKilled|Evicted|Unknown|CreateContainer|Invalid/i.test(s);

function Pods({ cluster }: { cluster: Cluster }) {
  const [ns, setNs] = useState('');
  const [filter, setFilter] = useState('');
  const [problemsOnly, setProblemsOnly] = useState(false);
  const pods = useCluster<Items<Pod>>(cluster.id, { kind: 'pods', namespace: ns, limit: 500 }, [ns], 15000);
  const usage = useCluster<Items<PodUsage> & { available: boolean; reason?: string }>(cluster.id, { kind: 'pod_metrics', namespace: ns }, [ns], 15000);
  const [describe, setDescribe] = useState<Pod | null>(null);
  const u = new Map((usage.data?.data?.items ?? []).map(x => [`${x.ns}/${x.name}`, x]));
  const rows = (pods.data?.data?.items ?? []).filter(p => (!filter || `${p.ns}/${p.name}`.toLowerCase().includes(filter.toLowerCase())) && (!problemsOnly || badPod(p.status)));
  return (
    <div className="grid">
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
        <input className="lv-select" placeholder="Filter by name…" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter pods" />
        <label className="check"><input type="checkbox" checked={problemsOnly} onChange={e => setProblemsOnly(e.target.checked)} />Problems only</label>
        <span className="grow" /><button className="btn sm" onClick={() => { pods.reload(); usage.reload(); }}><Icon name="refresh" size={14} />Refresh</button>
      </div>
      {usage.data && usage.data.data?.available === false && <p className="sm muted">{usage.data.data.reason} Pod usage columns are empty.</p>}
      <section className="card">
        <Loading busy={pods.busy && !pods.data} error={pods.error} retry={pods.reload} />
        {pods.data && (rows.length === 0 ? <p className="muted sm">No pods match.</p> : (
          <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Pod</th><th>Status</th><th>Ready</th><th className="num">Restarts</th><th className="num">CPU</th><th className="num">Memory</th><th>Node</th><th>Age</th></tr></thead><tbody>
            {rows.map(p => { const x = u.get(`${p.ns}/${p.name}`); return (
              <tr key={p.ns + p.name} className="click" onClick={() => setDescribe(p)}>
                <td><div className="name">{p.name}<small>{p.ns}</small></div></td>
                <td className={badPod(p.status) ? 'bad' : ''}><b>{p.status}</b></td><td>{p.ready}</td><td className={`num ${p.restarts > 5 ? 'warn' : ''}`}>{p.restarts}</td>
                <td className="num" title={p.cpu_req_m ? `requests ${p.cpu_req_m}m` : 'no CPU request'}>{x ? `${Math.round(x.cpu_m)}m` : '–'}</td>
                <td className="num" title={p.mem_lim_mib ? `limit ${p.mem_lim_mib} MiB` : 'no memory limit'}>{x ? `${Math.round(x.mem_mib)} MiB` : '–'}</td>
                <td className="sm">{p.node}</td><td className="sm">{timeAgo(p.created).replace(' ago', '')}</td></tr>); })}
          </tbody></table></div>))}
        <Trunc on={pods.data?.data?.truncated} />
      </section>
      {describe && <Describe cluster={cluster} resource="pod" ns={describe.ns} name={describe.name} pod={describe} onClose={() => setDescribe(null)} />}
    </div>
  );
}

type NodeRow = { name: string; ready: boolean; roles: string[]; version: string; os: string; kernel: string; runtime: string; arch: string; ip: string; unschedulable: boolean; taints: number;
  cpu_alloc_m: number; mem_alloc_mib: number; pods_cap: number; conditions: { type: string; status: string; reason: string; message: string }[] };
function Nodes({ cluster }: { cluster: Cluster }) {
  const lim = useLimits();
  const nodes = useCluster<Items<NodeRow>>(cluster.id, { kind: 'nodes' }, [], 20000);
  const usage = useCluster<Items<{ name: string; cpu_m: number; mem_mib: number }> & { available: boolean }>(cluster.id, { kind: 'node_metrics' }, [], 20000);
  const [describe, setDescribe] = useState<string | null>(null);
  const u = new Map((usage.data?.data?.items ?? []).map(x => [x.name, x]));
  return (
    <section className="card">
      <Loading busy={nodes.busy && !nodes.data} error={nodes.error} retry={nodes.reload} />
      {nodes.data && <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Node</th><th>Status</th><th>Roles</th><th style={{ minWidth: 130 }}>CPU</th><th style={{ minWidth: 130 }}>Memory</th><th>Version</th><th>Address</th></tr></thead><tbody>
        {(nodes.data.data?.items ?? []).map(n => { const x = u.get(n.name); const cp = x ? (x.cpu_m / n.cpu_alloc_m) * 100 : null; const mp = x ? (x.mem_mib / n.mem_alloc_mib) * 100 : null; const issues = n.conditions.filter(c => (c.type === 'Ready' ? c.status !== 'True' : c.status === 'True')); return (
          <tr key={n.name} className="click" onClick={() => setDescribe(n.name)}>
            <td><div className="name">{n.name}<small>{n.os}</small></div></td>
            <td><StatusPill status={n.ready && !issues.length ? 'up' : 'alert'} label={n.ready ? (issues.length ? issues.map(i => i.type).join(', ') : 'Ready') : 'Not ready'} />{n.unschedulable && <span className="tag">cordoned</span>}</td>
            <td className="sm">{n.roles.join(', ')}</td>
            <td>{cp != null ? <><div className="sm">{Math.round(x!.cpu_m)}m / {Math.round(n.cpu_alloc_m)}m</div><Meter value={cp} warnAt={lim.warn} badAt={lim.bad} /></> : <span className="muted sm">{Math.round(n.cpu_alloc_m)}m allocatable</span>}</td>
            <td>{mp != null ? <><div className="sm">{Math.round(x!.mem_mib)} / {Math.round(n.mem_alloc_mib)} MiB</div><Meter value={mp} warnAt={lim.warn} badAt={lim.bad} /></> : <span className="muted sm">{Math.round(n.mem_alloc_mib)} MiB allocatable</span>}</td>
            <td className="sm mono">{n.version}</td><td className="sm mono">{n.ip}</td></tr>); })}
      </tbody></table></div>}
      {usage.data && usage.data.data?.available === false && <p className="sm muted">Live usage needs metrics-server in the cluster.</p>}
      {describe && <Describe cluster={cluster} resource="node" ns="" name={describe} onClose={() => setDescribe(null)} />}
    </section>
  );
}

type Hpa = { ns: string; name: string; target: string; min: number; max: number; current: number; desired: number; metrics: { name?: string; current?: string; target?: string; type?: string }[] | string[]; last_scale: string | null; conditions: { type: string; status: string; reason: string; message: string }[] };
function Scaling({ cluster }: { cluster: Cluster }) {
  const [ns, setNs] = useState('');
  const hpa = useCluster<Items<Hpa>>(cluster.id, { kind: 'hpa', namespace: ns, limit: 500 }, [ns], 20000);
  const fmt = (m: Hpa['metrics'][number]) => typeof m === 'string' ? m : `${m.name ?? m.type}: ${m.current ?? '?'} / ${m.target ?? '?'}`;
  return (
    <div className="grid">
      <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
      <section className="card"><div className="card-head"><h2>Horizontal Pod Autoscalers</h2></div>
        <Loading busy={hpa.busy && !hpa.data} error={hpa.error} retry={hpa.reload} />
        {hpa.data && ((hpa.data.data?.items ?? []).length === 0 ? <p className="muted sm">No HPAs in this scope.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Target</th><th>Replicas</th><th>Metrics (current / target)</th><th>Last scaled</th></tr></thead><tbody>
          {(hpa.data.data?.items ?? []).map(h => { const limited = h.conditions.find(c => c.type === 'ScalingLimited' && c.status === 'True'); const broken = h.conditions.find(c => c.type === 'ScalingActive' && c.status === 'False'); return (
            <tr key={h.ns + h.name}><td><div className="name">{h.name}<small>{h.ns}</small></div></td><td className="sm">{h.target}</td>
              <td><b className={h.current >= h.max ? 'warn' : ''}>{h.current}</b> <span className="muted sm">(want {h.desired}; {h.min}–{h.max})</span>{limited && <div className="warn sm">{limited.reason}</div>}</td>
              <td className="sm">{(h.metrics as Hpa['metrics']).length ? (h.metrics as Hpa['metrics'][number][]).map((m, i) => <div key={i}>{fmt(m)}</div>) : <span className="muted">none</span>}{broken && <div className="bad sm">{broken.message || broken.reason}</div>}</td>
              <td className="sm">{timeAgo(h.last_scale)}</td></tr>); })}
        </tbody></table></div>)}
      </section>
    </div>
  );
}

function Network({ cluster }: { cluster: Cluster }) {
  const [ns, setNs] = useState('');
  const svc = useCluster<Items<{ ns: string; name: string; type: string; cluster_ip: string; external: string[]; ports: string[] }>>(cluster.id, { kind: 'services', namespace: ns, limit: 500 }, [ns], 30000);
  const ing = useCluster<Items<{ ns: string; name: string; class: string; hosts: string[]; address: string[]; tls: number }>>(cluster.id, { kind: 'ingresses', namespace: ns, limit: 500 }, [ns], 30000);
  const pvc = useCluster<Items<{ ns: string; name: string; status: string; capacity: string; class: string; volume: string }>>(cluster.id, { kind: 'pvcs', namespace: ns, limit: 500 }, [ns], 30000);
  const quotas = useCluster<Items<{ ns: string; name: string; resources: { name: string; hard: string; used: string }[] }>>(cluster.id, { kind: 'quotas', namespace: ns }, [ns], 60000);
  return (
    <div className="grid">
      <NamespaceSelect cluster={cluster} value={ns} onChange={setNs} />
      <section className="card"><div className="card-head"><h2>Services</h2></div>{svc.data && <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Type</th><th>Cluster IP</th><th>External</th><th>Ports</th></tr></thead><tbody>
        {(svc.data.data?.items ?? []).map(s => <tr key={s.ns + s.name}><td><div className="name">{s.name}<small>{s.ns}</small></div></td><td className="sm">{s.type}</td><td className="mono sm">{s.cluster_ip}</td><td className="mono sm">{s.external.join(', ') || '–'}</td><td className="mono sm">{s.ports.join(', ')}</td></tr>)}</tbody></table></div>}</section>
      <section className="card"><div className="card-head"><h2>Ingresses</h2></div>{ing.data && ((ing.data.data?.items ?? []).length === 0 ? <p className="muted sm">No ingresses.</p> : <table className="tbl"><thead><tr><th>Name</th><th>Class</th><th>Hosts</th><th>Address</th><th>TLS</th></tr></thead><tbody>
        {(ing.data.data?.items ?? []).map(i => <tr key={i.ns + i.name}><td><div className="name">{i.name}<small>{i.ns}</small></div></td><td className="sm">{i.class || '–'}</td><td className="mono sm">{i.hosts.join(', ')}</td><td className="mono sm">{i.address.join(', ') || '–'}</td><td>{i.tls ? 'yes' : 'no'}</td></tr>)}</tbody></table>)}</section>
      <section className="card"><div className="card-head"><h2>Persistent volume claims</h2></div>{pvc.data && ((pvc.data.data?.items ?? []).length === 0 ? <p className="muted sm">No claims.</p> : <table className="tbl"><thead><tr><th>Name</th><th>Status</th><th>Capacity</th><th>Class</th><th>Volume</th></tr></thead><tbody>
        {(pvc.data.data?.items ?? []).map(p => <tr key={p.ns + p.name}><td><div className="name">{p.name}<small>{p.ns}</small></div></td><td className={p.status !== 'Bound' ? 'warn' : ''}>{p.status}</td><td>{p.capacity || '–'}</td><td className="sm">{p.class}</td><td className="mono sm">{p.volume}</td></tr>)}</tbody></table>)}</section>
      {(quotas.data?.data?.items ?? []).length > 0 && <section className="card"><div className="card-head"><h2>Resource quotas</h2></div><table className="tbl"><tbody>
        {(quotas.data?.data?.items ?? []).flatMap(q => q.resources.map(r => <tr key={q.ns + q.name + r.name}><td className="sm">{q.ns}/{q.name}</td><td className="mono sm">{r.name}</td><td className="num">{r.used} / {r.hard}</td></tr>))}</tbody></table></section>}
    </div>
  );
}

type Ev = { ns: string; type: string; reason: string; object: string; message: string; count: number; last: string | null };
function Events({ cluster }: { cluster: Cluster }) {
  const [ns, setNs] = useState('');
  const [warn, setWarn] = useState(true);
  const ev = useCluster<Items<Ev>>(cluster.id, { kind: 'events', namespace: ns, warnings_only: warn, limit: 200 }, [ns, warn], 20000);
  return (
    <div className="grid">
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}><NamespaceSelect cluster={cluster} value={ns} onChange={setNs} /><label className="check"><input type="checkbox" checked={warn} onChange={e => setWarn(e.target.checked)} />Warnings only</label></div>
      <section className="card"><Loading busy={ev.busy && !ev.data} error={ev.error} retry={ev.reload} />
        {ev.data && ((ev.data.data?.items ?? []).length === 0 ? <p className="muted sm">No events.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>When</th><th>Reason</th><th>Object</th><th>Message</th></tr></thead><tbody>
          {(ev.data.data?.items ?? []).map((e, i) => <tr key={i}><td className="sm">{timeAgo(e.last)}{e.count > 1 && <small> ×{e.count}</small>}</td><td className={e.type === 'Warning' ? 'warn' : ''}><b>{e.reason}</b></td><td className="sm mono">{e.ns ? `${e.ns}/` : ''}{e.object}</td><td className="sm">{e.message}</td></tr>)}</tbody></table></div>)}
      </section>
    </div>
  );
}

/* ---------------------------------------------------------------- describe (secret-free: the agent redacts env values) */
function Describe({ cluster, resource, ns, name, pod, onClose }: { cluster: Cluster; resource: string; ns: string; name: string; pod?: Pod; onClose: () => void }) {
  const d = useCluster<{ object: unknown; events: Ev[] }>(cluster.id, { kind: 'describe', resource, namespace: ns, name }, [resource, ns, name]);
  const [showObject, setShowObject] = useState(false);
  return (
    <Modal title={`${resource} · ${name}`} onClose={onClose} wide>
      {pod && <div className="sm" style={{ marginBottom: 10 }}>
        <div className="muted">{pod.ns} · node {pod.node} · IP {pod.ip} · QoS {pod.qos} · owner {pod.owner || '–'}</div>
        <table className="tbl"><thead><tr><th>Container</th><th>State</th><th>Restarts</th><th>Image</th></tr></thead><tbody>
          {pod.containers.map(c => <tr key={c.name}><td>{c.name}</td><td className={c.ready ? '' : 'bad'}>{c.state}{c.reason && ` · ${c.reason}`}</td><td>{c.restarts}</td><td className="mono sm">{c.image}</td></tr>)}</tbody></table>
        <div className="muted" style={{ marginTop: 6 }}>Requests {pod.cpu_req_m}m / {pod.mem_req_mib} MiB · limits {pod.cpu_lim_m ? `${pod.cpu_lim_m}m` : 'none'} / {pod.mem_lim_mib ? `${pod.mem_lim_mib} MiB` : 'none'}</div>
      </div>}
      <Loading busy={d.busy && !d.data} error={d.error} retry={d.reload} />
      {d.data?.data && <>
        <h3 style={{ margin: '8px 0' }}>Events</h3>
        {d.data.data.events.length === 0 ? <p className="muted sm">No events for this object.</p> : <table className="tbl"><tbody>{d.data.data.events.map((e, i) => <tr key={i}><td className="sm">{timeAgo(e.last)}</td><td className={e.type === 'Warning' ? 'warn' : ''}><b>{e.reason}</b></td><td className="sm">{e.message}</td></tr>)}</tbody></table>}
        <div style={{ marginTop: 10 }}><button className="btn sm" onClick={() => setShowObject(!showObject)}>{showObject ? 'Hide' : 'Show'} full object (env values redacted)</button></div>
        {showObject && <pre className="codebox" style={{ maxHeight: 360, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{JSON.stringify(d.data.data.object, null, 2)}</pre>}
      </>}
    </Modal>
  );
}

/* ---------------------------------------------------------------- pod logs */
function PodLogs({ cluster }: { cluster: Cluster }) {
  const [ns, setNs] = useState('');
  const [pod, setPod] = useState('');
  const [container, setContainer] = useState('');
  const [previous, setPrevious] = useState(false);
  const [lines, setLines] = useState('200');
  const [since, setSince] = useState('0');
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState('');
  const [level, setLevel] = useState<'all' | 'error' | 'warn'>('all');
  const [live, setLive] = useState(false);
  const [wrap, setWrap] = useState(true);
  const [out, setOut] = useState<{ text: string; truncated: boolean; at: Date } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const pods = useCluster<Items<Pod>>(cluster.id, ns ? { kind: 'pods', namespace: ns, limit: 500 } : null, [ns]);
  const nsList = useCluster<Items<{ name: string }>>(cluster.id, { kind: 'namespaces' }, []);
  const allowed = (n: string) => cluster.log_policy.enabled && cluster.log_policy.include.some(p => glob(p, n)) && !cluster.log_policy.exclude.some(p => glob(p, n));
  const podRow = (pods.data?.data?.items ?? []).find(p => p.name === pod);
  const scroller = useRef<HTMLDivElement>(null);
  const seq = useRef(0);

  const fetchLogs = useCallback(async (override?: { filter?: string }) => {
    if (!ns || !pod) return;
    const mine = ++seq.current;
    setBusy(true);
    try {
      const filter = override?.filter ?? applied;
      const r = await ask<never>(cluster.id, { kind: 'logs', namespace: ns, name: pod, container, previous, lines: Number(lines), since_minutes: Number(since), grep: filter }, () => mine !== seq.current);
      setOut({ text: r.text ?? '', truncated: r.truncated, at: new Date() }); setError('');
    } catch (e) { if ((e as Error).message !== 'cancelled') setError((e as Error).message); } finally { if (mine === seq.current) setBusy(false); }
  }, [cluster.id, ns, pod, container, previous, lines, since, applied]);

  useEffect(() => { setOut(null); setContainer(''); if (pod) void fetchLogs(); }, [pod]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (!live) return; const t = window.setInterval(() => { if (!document.hidden) void fetchLogs(); }, 5000); return () => window.clearInterval(t); }, [live, fetchLogs]);
  useEffect(() => { const el = scroller.current; if (el && live) el.scrollTop = el.scrollHeight; }, [out, live]);

  const rows = out ? parse(out.text) : [];
  const shown = level === 'all' ? rows : rows.filter(r => r.level === level);
  const errors = rows.filter(r => r.level === 'error').length, warns = rows.filter(r => r.level === 'warn').length;
  return (
    <div className="lv">
      <div className="lv-filters">
        <select className="lv-select" value={ns} onChange={e => { setNs(e.target.value); setPod(''); setOut(null); }} aria-label="Namespace">
          <option value="">Choose a namespace…</option>
          {(nsList.data?.data?.items ?? []).map(n => <option key={n.name} value={n.name} disabled={!allowed(n.name)}>{n.name}{allowed(n.name) ? '' : '  (blocked by policy)'}</option>)}</select>
        <select className="lv-select" value={pod} onChange={e => setPod(e.target.value)} disabled={!ns} aria-label="Pod" style={{ minWidth: 220 }}>
          <option value="">{ns ? (pods.busy ? 'Loading pods…' : 'Choose a pod…') : 'Pod'}</option>{(pods.data?.data?.items ?? []).map(p => <option key={p.name} value={p.name}>{p.name}  ({p.status})</option>)}</select>
        {podRow && podRow.containers.length > 1 && <select className="lv-select" value={container} onChange={e => setContainer(e.target.value)} aria-label="Container"><option value="">All / default container</option>{podRow.containers.map(c => <option key={c.name} value={c.name}>{c.name}</option>)}</select>}
        <label className="check"><input type="checkbox" checked={previous} onChange={e => setPrevious(e.target.checked)} />Previous (crashed) container</label>
      </div>
      <form className="lv-filters" onSubmit={(e: FormEvent) => { e.preventDefault(); setApplied(search); void fetchLogs({ filter: search }); }}>
        <label className="lv-search"><Icon name="logs" size={15} /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search in logs…  (press Enter)" maxLength={200} aria-label="Search" /></label>
        <select className="lv-select" value={since} onChange={e => setSince(e.target.value)} aria-label="Time range"><option value="0">Any time</option><option value="15">Last 15 min</option><option value="60">Last hour</option><option value="360">Last 6 hours</option><option value="1440">Last 24 hours</option></select>
        <select className="lv-select" value={lines} onChange={e => setLines(e.target.value)} aria-label="Number of lines">{['100', '200', '500', '1000', '2000'].map(n => <option key={n} value={n}>{n} lines</option>)}</select>
        <button className="btn primary sm" disabled={busy || !pod}>Apply</button>
        <button type="button" className={`lv-live ${live ? 'on' : ''}`} onClick={() => setLive(!live)} aria-pressed={live}><i />{live ? 'Live' : 'Live off'}</button>
        <div className="lv-levels" role="group" aria-label="Level filter">
          <button type="button" className={level === 'all' ? 'on' : ''} onClick={() => setLevel('all')}>All</button>
          <button type="button" className={`err ${level === 'error' ? 'on' : ''}`} onClick={() => setLevel(level === 'error' ? 'all' : 'error')}>Errors <b>{errors}</b></button>
          <button type="button" className={`wrn ${level === 'warn' ? 'on' : ''}`} onClick={() => setLevel(level === 'warn' ? 'all' : 'warn')}>Warnings <b>{warns}</b></button>
        </div>
      </form>
      {cluster.restricted && <div className="lv-note"><p><Icon name="shield" size={14} />Log access is limited by this cluster’s policy ({cluster.log_policy.enabled ? `only ${cluster.log_policy.include.join(', ')}${cluster.log_policy.exclude.length ? `, not ${cluster.log_policy.exclude.join(', ')}` : ''}` : 'off'}).</p></div>}
      {error && <div className="lv-error" role="alert"><Icon name="alert" size={15} />{error}<button className="btn sm" onClick={() => void fetchLogs()}>Retry</button></div>}
      <div className="lv-body">
        <div className="lv-cols"><span>#</span><span>Time</span><span>Level</span><span>Message</span></div>
        {!pod ? <div className="lv-empty"><Icon name="logs" size={26} /><h3>Choose a namespace and pod</h3><p>Logs are fetched from the cluster when you ask and are never stored on the control plane. Every read is recorded in the audit log.</p></div>
          : !out ? <div className="lv-skel">{Array.from({ length: 12 }, (_, i) => <i key={i} style={{ width: `${30 + ((i * 53) % 65)}%` }} />)}</div>
          : shown.length === 0 ? <div className="lv-empty"><Icon name="logs" size={26} /><h3>{rows.length ? 'No lines at this level' : applied ? 'No lines match your search' : 'No log output'}</h3></div>
          : <div className={`lv-scroll ${wrap ? 'wrap' : ''}`} ref={scroller}>{shown.map(r => (
            <div key={r.n} className={`lv-row ${r.level}`}><span className="n">{r.n}</span><span className="t" title={r.tsTitle}>{r.ts}</span>
              <span className="l">{r.level && <em className={r.level}>{LEVEL_LABEL[r.level]}</em>}</span><span className="m"><Highlight text={r.msg} term={applied} /></span></div>))}</div>}
      </div>
      <div className="lv-foot">
        <span><b>{shown.length.toLocaleString()}</b>{shown.length !== rows.length ? ` of ${rows.length.toLocaleString()}` : ''} lines</span>
        {out?.truncated && <span className="warn">newest part only</span>}{out && <span className="muted">fetched {out.at.toLocaleTimeString()}</span>}
        <span className="grow" /><label className="check"><input type="checkbox" checked={wrap} onChange={e => setWrap(e.target.checked)} />Wrap lines</label>
        <button className="btn ghost sm" onClick={() => void navigator.clipboard?.writeText(shown.map(r => `${r.ts} ${r.msg}`.trim()).join('\n'))} disabled={!shown.length}>Copy</button>
      </div>
    </div>
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
