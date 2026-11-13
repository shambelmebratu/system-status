'use client';

import { FormEvent, useEffect, useState } from 'react';
import { AvailabilityPanel } from '../components/availability';
import { AreaChart, Ring } from '../components/charts';
import { JoinCommands, expiryText, useActiveEnrollment, useControlPlaneUrl } from '../components/join';
import { LogsPanel } from '../components/logs';
import { LogPolicyCard } from '../components/logpolicy';
import { CodeBox, Empty, Field, Icon, Meter, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, useLimits, usePoll } from '../lib/app';
import { bytesPerSecond, duration, ms, pct, timeAgo } from '../lib/format';
import type { Incident, Mode, Range, Server, ServerHistory } from '../lib/types';
import { IncidentList } from './Overview';

const MODE_LABEL: Record<Mode, string> = { push: 'Agent · push', agent: 'Agent · pull', ping: 'Ping only' };

export function Servers() {
  const { data, route, go, canOperate } = useApp();
  if (!data) return <p className="muted">Loading…</p>;
  if (route[1] === 'new' && canOperate) return <><ServerList /><ServerWizard onClose={() => go('servers')} /></>;
  if (route[1]) {
    const server = data.servers.find(s => s.id === Number(route[1]));
    return server ? <ServerDetail server={server} /> : <Empty title="Server not found" action={<button className="btn" onClick={() => go('servers')}>Back to servers</button>} />;
  }
  return <ServerList />;
}

function ServerList() {
  const { data, go, canOperate } = useApp();
  const lim = useLimits();
  const servers = data!.servers;
  return (
    <>
      <div className="topbar"><h1>Servers</h1><span className="grow" />{canOperate && <button className="btn primary" onClick={() => go('servers/new')}><Icon name="plus" size={15} />Add server</button>}</div>
      {servers.length === 0 ? <div className="card"><Empty title="No servers yet" action={canOperate ? <button className="btn primary" onClick={() => go('servers/new')}>Install your first agent</button> : undefined}>Add a server to see live CPU, memory, disk and network metrics.</Empty></div> : (
        <div className="tilegrid">
          {servers.map(s => {
            const m = s.last_metrics;
            return (
              <div key={s.id} className="card tile" onClick={() => go(`servers/${s.id}`)}>
                <div className="tile-top"><div className="grow"><div className="name">{s.name}</div><small className="muted">{m?.hostname || s.host || 'waiting for first report'}</small></div><StatusPill status={s.last_status} /></div>
                {m?.cpu != null ? (
                  <div className="minis">
                    {(['cpu', 'memory', 'disk'] as const).map(k => <div key={k} className="mini">{k === 'cpu' ? 'CPU' : k === 'memory' ? 'Memory' : 'Disk'}<b>{pct(m[k], 0)}</b><Meter value={m[k]!} warnAt={s[`${k}_threshold` as const] * (lim.warn / lim.bad)} badAt={s[`${k}_threshold` as const]} /></div>)}
                  </div>
                ) : <div className="muted sm" style={{ minHeight: 48 }}>{s.last_status === 'down' ? s.last_error : s.monitor_mode === 'ping' ? `Latency ${ms(m?.latency_ms)}` : 'No metrics received yet.'}</div>}
                <div className="foot"><span className="tag">{MODE_LABEL[s.monitor_mode]}</span><span>{s.monitor_mode === 'push' ? `seen ${timeAgo(s.last_seen_at)}` : `checked ${timeAgo(s.last_checked_at)}`}</span></div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

function ServerDetail({ server }: { server: Server }) {
  const { go, toast, refresh, canOperate, confirm } = useApp();
  const [range, setRange] = useState<Range>('24h');
  const [editing, setEditing] = useState(false);
  const [rotated, setRotated] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'logs'>('overview');
  const canLogs = canOperate && server.monitor_mode === 'push' && !!server.last_metrics?.capabilities?.includes('logs');
  const history = usePoll(() => api<ServerHistory>(`/servers/${server.id}/history?range=${range}`), [server.id, range], 20000);
  const incidents = usePoll(() => api<Incident[]>('/incidents?limit=200'), [server.id], 30000);
  const m = server.last_metrics;
  const h = history.value;
  const showDate = range === '7d' || range === '30d';
  const mine = (incidents.value || []).filter(i => i.target_type === 'server' && i.target_id === server.id).slice(0, 6);
  const never = server.monitor_mode === 'push' && !server.last_seen_at;

  async function remove() {
    if (!(await confirm(`Remove ${server.name}?\n\nIts history is deleted too. This cannot be undone.`))) return;
    try { await del(`/servers/${server.id}`); toast('Server removed'); await refresh(); go('servers'); } catch (e) { toast((e as Error).message, true); }
  }
  async function rotate() {
    if (!(await confirm('Rotate this server’s agent token?\n\nA new token is delivered to the agent automatically at its next report, and the old one stops working as soon as the agent has switched. Nothing needs to be reinstalled.'))) return;
    try { toast((await post<{ detail?: string }>(`/servers/${server.id}/rotate-token`)).detail ?? 'Token rotation started'); await refresh(); } catch (e) { toast((e as Error).message, true); }
  }
  async function revokeNow() {
    if (!(await confirm('Revoke this token NOW?\n\nUse this if the token may be stolen. The old token stops working immediately and the agent goes offline until you install the new token on the server.'))) return;
    try { setRotated((await post<{ install_token: string }>(`/servers/${server.id}/rotate-token?immediate=true`)).install_token); await refresh(); } catch (e) { toast((e as Error).message, true); }
  }

  return (
    <>
      <div className="topbar">
        <button className="btn ghost sm" onClick={() => go('servers')}><Icon name="back" size={15} />Servers</button>
        <h1>{server.name}</h1><StatusPill status={server.last_status} /><span className="tag">{MODE_LABEL[server.monitor_mode]}</span>
        <span className="grow" />
        {canOperate && server.monitor_mode !== 'ping' && <button className="btn sm" onClick={rotate} disabled={!!server.token_rotation_pending} title="Delivered to the agent automatically; nothing to reinstall">{server.token_rotation_pending ? 'Rotation pending…' : 'Rotate token'}</button>}
        {canOperate && server.monitor_mode !== 'ping' && <button className="btn sm danger" onClick={revokeNow} title="Invalidate the current token immediately (if it may be stolen)">Revoke now</button>}
        {canOperate && <button className="btn sm" onClick={() => setEditing(true)}>Edit</button>}
        {canOperate && <button className="btn sm danger" onClick={remove}>Remove</button>}
      </div>

      {canLogs && <div className="seg" style={{ marginBottom: 16 }}><button className={tab === 'overview' ? 'on' : ''} onClick={() => setTab('overview')}>Overview</button><button className={tab === 'logs' ? 'on' : ''} onClick={() => setTab('logs')}>Logs</button></div>}
      {server.last_status === 'down' && server.last_error && <div className="err" style={{ marginBottom: 16 }}>{server.last_error}</div>}
      {tab === 'logs' && canLogs && <LogsPanel serverId={server.id} />}
      {never && (
        <div className="card" style={{ marginBottom: 16 }}><div className="card-head"><h2>Waiting for the agent</h2></div>
          <p className="muted">No report has been received yet. Install the agent with the token shown when this server was created (use <b>Rotate token</b> to get a new one).</p></div>
      )}

      <div className="grid g-side" style={tab === 'logs' && canLogs ? { display: 'none' } : undefined}>
        <div className="grid">
          <section className="card">
            <div className="card-head"><h2>Current</h2><span className="grow" /><span className="sm muted">{server.monitor_mode === 'push' ? `last report ${timeAgo(server.last_seen_at)}` : `checked ${timeAgo(server.last_checked_at)}`}</span></div>
            {m?.cpu != null ? (
              <div className="rings">
                <Ring label="CPU" value={m.cpu} threshold={server.cpu_threshold} />
                <Ring label="Memory" value={m.memory} threshold={server.memory_threshold} />
                <Ring label="Disk" value={m.disk} threshold={server.disk_threshold} />
                <Ring label="Load" value={Math.min(100, ((m.load ?? 0) / server.load_threshold) * 100)} threshold={100} display={String(m.load ?? '–')} />
                <Ring label="Swap" value={m.swap} threshold={server.swap_threshold} />
              </div>
            ) : server.monitor_mode === 'ping' ? (
              <div className="grid g3">
                <div className="stat"><span className="label">Status</span><span className="value" style={{ fontSize: 22 }}>{server.last_status === 'up' ? 'Reachable' : server.last_status === 'down' ? 'Unreachable' : 'Pending'}</span><span className="sub">ICMP ping to {server.host}</span></div>
                <div className="stat"><span className="label">Round-trip now</span><span className="value">{ms(m?.latency_ms)}</span><span className="sub">avg {ms(h?.latency_avg)} · p95 {ms(h?.latency_p95)}</span></div>
                <div className="stat"><span className="label">Availability {range}</span><span className="value">{pct(h?.uptime_pct, 2)}</span><span className="sub">max latency {ms(h?.latency_max)}</span></div>
              </div>
            ) : <p className="muted">No metrics yet.</p>}
          </section>

          {server.monitor_mode === 'ping' && (
            <>
              <div className="seg" style={{ alignSelf: 'flex-start' }}>{(['1h', '6h', '24h', '7d'] as Range[]).map(r => <button key={r} className={range === r ? 'on' : ''} onClick={() => setRange(r)}>{r}</button>)}</div>
              <section className="card"><div className="card-head"><h2>Ping latency</h2></div>
                <AreaChart points={h?.latency_points ?? []} height={200} unit="ms" showDate={showDate} series={[{ key: 'latency', label: 'Latency', color: 'var(--accent)', format: v => `${Math.round(v)} ms` }]} /></section>
            </>
          )}

          {server.monitor_mode !== 'ping' && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div className="seg">{(['1h', '6h', '24h', '7d'] as Range[]).map(r => <button key={r} className={range === r ? 'on' : ''} onClick={() => setRange(r)}>{r}</button>)}</div>
                {h && <span className="muted sm">{h.samples} samples · uptime {pct(h.uptime_pct, 2)}</span>}
              </div>
              <section className="card"><div className="card-head"><h2>CPU & memory</h2><span className="grow" /><Legend items={[['CPU', 'var(--c1)'], ['Memory', 'var(--c2)']]} /></div>
                <AreaChart points={h?.points ?? []} unit="%" yMax={100} showDate={showDate} series={[{ key: 'cpu', label: 'CPU', color: 'var(--c1)' }, { key: 'memory', label: 'Memory', color: 'var(--c2)' }]} /></section>
              <div className="grid g2">
                <section className="card"><div className="card-head"><h2>Load average</h2></div>
                  <AreaChart points={h?.points ?? []} height={150} showDate={showDate} series={[{ key: 'load', label: 'Load', color: 'var(--c3)' }]} /></section>
                <section className="card"><div className="card-head"><h2>Disk & swap</h2><span className="grow" /><Legend items={[['Disk', 'var(--c4)'], ['Swap', 'var(--c5)']]} /></div>
                  <AreaChart points={h?.points ?? []} height={150} unit="%" yMax={100} showDate={showDate} series={[{ key: 'disk', label: 'Disk', color: 'var(--c4)' }, { key: 'swap', label: 'Swap', color: 'var(--c5)' }]} /></section>
              </div>
              <section className="card"><div className="card-head"><h2>Network</h2><span className="grow" /><Legend items={[['Receive', 'var(--c1)'], ['Send', 'var(--c4)']]} /></div>
                <AreaChart points={h?.points ?? []} height={150} showDate={showDate} series={[{ key: 'net_rx_bps', label: 'Receive', color: 'var(--c1)', format: bytesPerSecond }, { key: 'net_tx_bps', label: 'Send', color: 'var(--c4)', format: bytesPerSecond }]} /></section>
            </>
          )}
          <AvailabilityPanel kind="servers" id={server.id} />
        </div>

        <div className="grid" style={{ alignContent: 'start' }}>
          <section className="card">
            <div className="card-head"><h2>System</h2></div>
            <table className="tbl"><tbody>
              <tr><td className="muted">Hostname</td><td>{m?.hostname || server.host || '–'}</td></tr>
              {m?.platform && <tr><td className="muted">Platform</td><td className="sm">{m.platform}</td></tr>}
              {server.monitor_mode !== 'ping' && <>
                <tr><td className="muted">CPU cores</td><td>{m?.cpu_count ?? '–'}</td></tr>
                <tr><td className="muted">Uptime</td><td>{m?.uptime_seconds != null ? duration(m.uptime_seconds) : '–'}</td></tr>
                <tr><td className="muted">Network</td><td>↓ {bytesPerSecond(m?.net_rx_bps)} · ↑ {bytesPerSecond(m?.net_tx_bps)}</td></tr>
                <tr><td className="muted">Agent</td><td>{m?.agent_version ? `v${m.agent_version}` : '–'}</td></tr>
              </>}
              {server.monitor_mode !== 'ping' && <>
                <tr><td className="muted">Agent token</td><td>{server.token_issued_at ? `issued ${timeAgo(server.token_issued_at)}` : 'age unknown'}{server.token_rotation_pending && <> · <span className="warn">rotation pending</span></>}</td></tr>
                {server.last_agent_ip && <tr><td className="muted">Last seen from</td><td className="mono">{server.last_agent_ip}</td></tr>}
              </>}
              <tr><td className="muted">Status page</td><td>{server.public ? 'Public' : 'Private'}</td></tr>
              <tr><td className="muted">Interval</td><td>{server.check_interval_seconds}s</td></tr>
              <tr><td className="muted">Availability 24h</td><td>{pct(server.uptime_24h, 2)}</td></tr>
            </tbody></table>
          </section>
          {server.monitor_mode !== 'ping' && <section className="card">
            <div className="card-head"><h2>Top processes</h2></div>
            {m?.processes?.length ? <table className="tbl"><thead><tr><th>Process</th><th className="num">CPU</th><th className="num">Mem</th></tr></thead><tbody>
              {m.processes.slice(0, 8).map(p => <tr key={`${p.pid}-${p.name}`}><td><div className="name">{p.name}<small>PID {p.pid}</small></div></td><td className="num">{pct(p.cpu, 1)}</td><td className="num">{p.memory != null ? pct(p.memory, 1) : '–'}</td></tr>)}
            </tbody></table> : <p className="muted sm">No process data.</p>}
          </section>}
          {canLogs && <LogPolicyCard serverId={server.id} />}
          <section className="card"><div className="card-head"><h2>Incidents</h2></div>{mine.length ? <IncidentList items={mine} onSelect={() => undefined} /> : <p className="muted sm">No incidents recorded.</p>}</section>
        </div>
      </div>
      {editing && <ServerWizard existing={server} onClose={() => setEditing(false)} />}
      {rotated && <Modal title="New agent token" onClose={() => setRotated(null)}><InstallInstructions token={rotated} serverId={server.id} /></Modal>}
    </>
  );
}

function Legend({ items }: { items: [string, string][] }) {
  return <div className="legend">{items.map(([label, color]) => <span key={label}><i style={{ background: color }} />{label}</span>)}</div>;
}

/* ------------------------------------------------------------------ add / edit */

type Thresholds = { cpu: string; memory: string; disk: string; load: string; swap: string; process: string };

function ServerWizard({ existing, onClose }: { existing?: Server; onClose: () => void }) {
  const { data, toast, refresh, go } = useApp();
  const defaults = data!.threshold_defaults;
  const [mode, setMode] = useState<Mode | null>(existing ? existing.monitor_mode : null);
  const [name, setName] = useState(existing?.name ?? '');
  const [host, setHost] = useState(existing?.host ?? '');
  const [interval, setIntervalValue] = useState(String(existing?.check_interval_seconds ?? defaults.server_interval_seconds));
  const [endpoint, setEndpoint] = useState(existing?.endpoint ?? '');
  const [token, setToken] = useState('');
  const [processNames, setProcessNames] = useState(existing?.process_names ?? '');
  const [isPublic, setPublic] = useState(existing?.public ?? false);
  const [th, setTh] = useState<Thresholds>({
    cpu: String(existing?.cpu_threshold ?? defaults.cpu), memory: String(existing?.memory_threshold ?? defaults.memory), disk: String(existing?.disk_threshold ?? defaults.disk),
    load: String(existing?.load_threshold ?? defaults.load), swap: String(existing?.swap_threshold ?? defaults.swap), process: String(existing?.process_threshold ?? defaults.process),
  });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<Server | null>(null);
  const [joining, setJoining] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    const body = {
      name, host, monitor_mode: mode, check_interval_seconds: Number(interval), endpoint: mode === 'agent' ? endpoint : '', agent_token: mode === 'agent' ? token : '',
      public: isPublic, process_names: processNames, cpu_threshold: Number(th.cpu), memory_threshold: Number(th.memory), disk_threshold: Number(th.disk),
      load_threshold: Number(th.load), swap_threshold: Number(th.swap), process_threshold: Number(th.process),
    };
    try {
      if (existing) { await put(`/servers/${existing.id}`, body); toast('Server updated'); await refresh(); onClose(); }
      else {
        const result = await post<Server>('/servers', body);
        await refresh();
        if (result.install_token) setCreated(result); else { toast('Server added'); go(`servers/${result.id}`); }
      }
    } catch (caught) { setError((caught as Error).message); }
    finally { setBusy(false); }
  }

  if (created) return <Modal title={`Install the agent on ${created.name}`} onClose={() => { onClose(); go(`servers/${created.id}`); }} wide><InstallInstructions token={created.install_token!} serverId={created.id} /></Modal>;

  if (joining) return <JoinModal onClose={onClose} />;
  if (!mode) {
    return (
      <Modal title="Add a server" onClose={onClose}>
        <p className="muted">How do you want to monitor it?</p>
        <div className="method">
          <button onClick={() => setJoining(true)}><b>Install agent <span className="tag">recommended</span></b><span>One command on the server. It registers itself and reports CPU, memory, disk, network and processes. No inbound ports needed.</span></button>
          <button onClick={() => setMode('ping')}><b>Ping only</b><span>Just check that a host answers ping. Nothing to install: enter an IP or hostname.</span></button>
          <button onClick={() => setMode('agent')}><b>Advanced: pull agent</b><span>The control plane polls an agent’s /metrics endpoint. Needs that port to be reachable from here.</span></button>
        </div>
      </Modal>
    );
  }

  const metrics = mode !== 'ping';
  return (
    <Modal title={existing ? `Edit ${existing.name}` : `Add server · ${MODE_LABEL[mode]}`} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="form-grid">
          <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder="web-01" required autoFocus /></Field>
          {mode !== 'push' && <Field label="Host / IP"><input value={host} onChange={e => setHost(e.target.value)} placeholder="10.0.0.12" required /></Field>}
          <Field label="Interval (seconds)" hint={mode === 'push' ? 'How often the agent reports.' : undefined}><input type="number" min={5} max={86400} value={interval} onChange={e => setIntervalValue(e.target.value)} required /></Field>
          {mode === 'agent' && <>
            <Field label="Agent URL"><input value={endpoint} onChange={e => setEndpoint(e.target.value)} placeholder="http://10.0.0.12:9100" required /></Field>
            <Field label="Agent token" hint={existing ? 'Leave blank to keep the saved token.' : '32+ characters (openssl rand -hex 32)'}><input type="password" value={token} onChange={e => setToken(e.target.value)} required={!existing} minLength={token ? 32 : undefined} /></Field>
          </>}
        </div>
        {metrics && (
          <>
            <h3 className="muted sm" style={{ textTransform: 'uppercase', letterSpacing: '.6px' }}>Alert thresholds</h3>
            <div className="form-grid">
              {([['cpu', 'CPU %'], ['memory', 'Memory %'], ['disk', 'Disk %'], ['load', 'Load (1m)'], ['swap', 'Swap %'], ['process', 'Process CPU %']] as const).map(([k, label]) =>
                <Field key={k} label={label} hint={k === 'process' ? 'Per core: 100 = one full core.' : undefined}><input type="number" step="any" min={0} value={th[k]} onChange={e => setTh({ ...th, [k]: e.target.value })} required /></Field>)}
              <Field label="Watch processes" hint="Comma-separated names; blank = any process."><input value={processNames} onChange={e => setProcessNames(e.target.value)} placeholder="nginx, postgres" /></Field>
            </div>
          </>
        )}
        <label className="check"><input type="checkbox" checked={isPublic} onChange={e => setPublic(e.target.checked)} />Show on the public status page <span className="muted">(name, status and uptime only)</span></label>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          {!existing && <button type="button" className="btn ghost" onClick={() => setMode(null)}>Back</button>}
          <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : existing ? 'Save changes' : mode === 'push' ? 'Create & get install command' : 'Add server'}</button>
        </div>
      </form>
    </Modal>
  );
}

function JoinModal({ onClose }: { onClose: () => void }) {
  const { data, go } = useApp();
  const lim = useLimits();
  const [base, setBase] = useControlPlaneUrl();
  const enrollment = useActiveEnrollment();
  const [opened] = useState(() => Date.now());
  const joined = (data?.servers ?? []).filter(s => s.monitor_mode === 'push' && new Date((s as unknown as { created_at: string }).created_at).getTime() >= opened - 5000);
  const local = /localhost|127\.0\.0\.1/.test(base);
  const e = enrollment.active;
  return (
    <Modal title="Install the agent on a server" onClose={onClose} wide>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <ol className="steps">
          <li><b>Run this one command on the server</b>
            {enrollment.error ? <div className="err">{enrollment.error}</div>
              : !enrollment.items ? <p className="muted sm">Loading…</p>
              : !e ? <div className="banner">No active install link. A link is only created when you need one and works for {lim.enrollDefault} minutes. <button className="btn sm primary" style={{ marginLeft: 8 }} disabled={enrollment.busy} onClick={() => void enrollment.generate()}>Generate install command</button></div>
              : <JoinCommands token={e.token} base={base} />}
          </li>
          <li><b>That’s it</b><span className="sm muted">The server registers itself under its hostname and appears below within seconds. You can rename it, set alert thresholds or add it to the status page afterwards. Run the same command on as many servers as you like.</span></li>
        </ol>
        {local && <div className="banner">This dashboard is open on <b>localhost</b>, which other servers can’t reach. Set <code>PUBLIC_URL</code> in the control plane’s <code>.env</code> to its real address, or edit it here:<input style={{ marginTop: 8, width: '100%' }} className="field" value={base} onChange={ev => setBase(ev.target.value.replace(/\/$/, ''))} /></div>}
        {e && <div className="sm muted">For safety this link is random and short-lived: <b>{expiryText(e)}</b>. Anyone who has it can add a server until then; {e.uses} server{e.uses === 1 ? '' : 's'} joined so far. <button className="btn ghost sm" onClick={() => void enrollment.generate()}>New link</button> <button className="btn ghost sm" onClick={() => enrollment.revoke(e.id)}>Revoke</button> <button className="btn ghost sm" onClick={() => go('settings')}>Manage join tokens</button></div>}
        <div className="waiting">
          {joined.length === 0 ? <><span className="spinner" />Waiting for a server to join… (this page updates automatically)</>
            : <div>{joined.map(j => <div key={j.id}><span className="good">●</span> <b>{j.name}</b> joined{j.last_seen_at ? ` · reporting (${timeAgo(j.last_seen_at)})` : ' · waiting for its first report'} <button className="btn sm ghost" onClick={() => { onClose(); go(`servers/${j.id}`); }}>Open</button></div>)}</div>}
        </div>
      </div>
    </Modal>
  );
}

function InstallInstructions({ token, serverId }: { token: string; serverId: number }) {
  const { data } = useApp();
  const [base, setBase] = useState('');
  const [tab, setTab] = useState<'linux' | 'docker'>('linux');
  useEffect(() => {
    setBase(window.location.origin);
    // PUBLIC_URL (set in the control plane's .env) wins over whatever address this browser used.
    api<{ public_url?: string }>('/branding').then(b => b.public_url && setBase(b.public_url)).catch(() => undefined);
  }, []);
  const server = data?.servers.find(s => s.id === serverId);
  const connected = !!server?.last_seen_at;
  const local = /localhost|127\.0\.0\.1/.test(base);
  const linux = `curl -fsSL ${base}/api/agent/install.sh | sudo SMWATCH_URL=${base} SMWATCH_TOKEN=${token} bash`;
  const docker = `docker run -d --name sm-watch-agent --restart unless-stopped --pid host \\
  -v /:/host:ro -e SMWATCH_URL=${base} -e AGENT_TOKEN=${token} \\
  -e AGENT_HOST_ROOT=/host -e AGENT_PROCFS_PATH=/host/proc -e AGENT_DISK_PATH=/host \\
  python:3.12-slim sh -c "pip install -q psutil && python -c \\"import urllib.request as u; u.urlretrieve('${base}/api/agent/agent.py','/agent.py')\\" && exec python /agent.py"`;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="banner">The token is shown <b>once</b>. Copy the command now; you can issue a new token later with “Rotate token”.</div>
      <Field label="Control plane URL (must be reachable from the server you are installing on)" hint="Set PUBLIC_URL in the control plane's .env to make this the default."><input value={base} onChange={e => setBase(e.target.value.replace(/\/$/, ''))} /></Field>
      {local && <div className="banner">This URL points at localhost. Replace it with your control plane’s public hostname or LAN address, or the other server won’t be able to reach it.</div>}
      <div className="seg" style={{ alignSelf: 'flex-start' }}><button className={tab === 'linux' ? 'on' : ''} onClick={() => setTab('linux')}>Linux (recommended)</button><button className={tab === 'docker' ? 'on' : ''} onClick={() => setTab('docker')}>Docker</button></div>
      {tab === 'linux' ? (
        <ol className="steps">
          <li><b>Paste this on the server (as a sudo user)</b><CodeBox value={linux} /><span className="sm muted">It installs any missing prerequisites, <b>tests the connection and token first</b>, then starts a systemd service that restarts automatically. Re-running it updates the agent.</span></li>
          <li><b>Confirm</b><span className="sm muted">This page flips to “Agent connected” within seconds. To check later on the server:</span><CodeBox value={`curl -fsSL ${base}/api/agent/install.sh | sudo bash -s -- status`} /></li>
          <li><b>Remove</b><CodeBox value={`curl -fsSL ${base}/api/agent/install.sh | sudo bash -s -- uninstall`} /></li>
        </ol>
      ) : (
        <ol className="steps">
          <li><b>Run on any Docker host</b><CodeBox value={docker} /><span className="sm muted">No repo or image build needed. It mounts the host read-only so metrics describe the host, not the container. Logs: <code>docker logs -f sm-watch-agent</code></span></li>
          <li><b>Remove</b><CodeBox value="docker rm -f sm-watch-agent" /></li>
        </ol>
      )}
      <div className="waiting">{connected ? <><span className="good">●</span><b>Agent connected</b> · first report {timeAgo(server?.last_seen_at)}</> : <><span className="spinner" />Waiting for the first report… (checks every 10s)</>}</div>
    </div>
  );
}
