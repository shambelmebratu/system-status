'use client';

import { useEffect, useState } from 'react';
import { LogsPanel } from '../components/logs';
import { Empty } from '../components/ui';
import { useApp } from '../lib/app';

export function Logs() {
  const { data, go, route } = useApp();
  const servers = (data?.servers ?? []).filter(s => s.monitor_mode === 'push' && s.last_metrics?.capabilities?.includes('logs'));
  const [id, setId] = useState<number | null>(route[1] ? Number(route[1]) : null);
  useEffect(() => { if (id == null && servers.length) setId(servers[0].id); }, [id, servers]);
  if (!data) return <p className="muted">Loading…</p>;
  return (
    <>
      <div className="topbar"><h1>Logs</h1><span className="grow" />
        {servers.length > 0 && <label className="field" style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>Server
          <select value={id ?? ''} onChange={e => setId(Number(e.target.value))} style={{ minWidth: 220 }}>{servers.map(s => <option key={s.id} value={s.id}>{s.name}{s.last_status === 'down' ? ' (down)' : ''}</option>)}</select></label>}
      </div>
      {servers.length === 0 ? <div className="card"><Empty title="No servers with log access yet" action={<button className="btn primary" onClick={() => go('servers/new')}>Install an agent</button>}>
        Logs are read on demand by the SM-Watch agent: Docker container logs, the system journal and log files such as nginx. Install the agent on a server (the machine running SM-Watch is included automatically).</Empty></div>
        : id != null && <LogsPanel key={id} serverId={id} />}
    </>
  );
}
