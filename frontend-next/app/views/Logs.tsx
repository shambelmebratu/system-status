'use client';

import { useEffect, useState } from 'react';
import { LogsPanel } from '../components/logs';
import { LogPolicyButton } from '../components/logpolicy';
import { Empty } from '../components/ui';
import { useApp } from '../lib/app';

export function Logs() {
  const { data, go, route, isAdmin } = useApp();
  const [reloadKey, setReloadKey] = useState(0);
  const servers = (data?.servers ?? []).filter(s => s.monitor_mode === 'push' && s.last_metrics?.capabilities?.includes('logs'));
  const [id, setId] = useState<number | null>(route[1] ? Number(route[1]) : null);
  useEffect(() => { if (id == null && servers.length) setId(servers[0].id); }, [id, servers]);
  if (!data) return <p className="muted">Loading…</p>;
  const current = servers.find(s => s.id === id);
  const picker = servers.length > 0 && (
    <label className="lgx-server" title="Server">
      <span className="lv-dot" data-state={current?.last_status === 'down' ? 'exited' : 'running'} />
      <select value={id ?? ''} onChange={e => setId(Number(e.target.value))} aria-label="Server">{servers.map(s => <option key={s.id} value={s.id}>{s.name}{s.last_status === 'down' ? ' (down)' : ''}</option>)}</select>
      <span className="caret">▾</span>
    </label>);
  return (
    <>
      <div className="topbar lgx-top"><div><h1>Logs</h1><p className="muted sm">Read live from each server’s agent: containers, the system journal and log files. Nothing is stored.</p></div></div>
      {servers.length === 0 ? <div className="card"><Empty title="No servers with log access yet" action={<button className="btn primary" onClick={() => go('servers/new')}>Install an agent</button>}>
        Logs are read on demand by the SM-Watch agent: Docker container logs, the system journal and log files such as nginx. Install the agent on a server (the machine running SM-Watch is included automatically).</Empty></div>
        : id != null && <LogsPanel key={`${id}-${reloadKey}`} serverId={id} lead={picker} trail={isAdmin ? <LogPolicyButton serverId={id} onSaved={() => setReloadKey(k => k + 1)} /> : undefined} />}
    </>
  );
}
