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
  return (
    <>
      <div className="topbar"><div><h1>Logs</h1><p className="muted sm">Read on demand from the server’s agent. Nothing is stored.</p></div><span className="grow" />
        {isAdmin && id != null && <LogPolicyButton serverId={id} onSaved={() => setReloadKey(k => k + 1)} />}
        {servers.length > 0 && <label className="lv-target" style={{ flex: '0 0 auto', minWidth: 260, paddingRight: 4 }}><span className="lv-dot" data-state={servers.find(s => s.id === id)?.last_status === 'down' ? 'exited' : 'running'} />
          <select value={id ?? ''} onChange={e => setId(Number(e.target.value))} aria-label="Server" style={{ border: 0, background: 'transparent', padding: '8px 8px 8px 0', fontWeight: 600, color: 'var(--ink)', flex: 1 }}>{servers.map(s => <option key={s.id} value={s.id}>{s.name}{s.last_status === 'down' ? ' (down)' : ''}</option>)}</select></label>}
      </div>
      {servers.length === 0 ? <div className="card"><Empty title="No servers with log access yet" action={<button className="btn primary" onClick={() => go('servers/new')}>Install an agent</button>}>
        Logs are read on demand by the SM-Watch agent: Docker container logs, the system journal and log files such as nginx. Install the agent on a server (the machine running SM-Watch is included automatically).</Empty></div>
        : id != null && <LogsPanel key={`${id}-${reloadKey}`} serverId={id} />}
    </>
  );
}
