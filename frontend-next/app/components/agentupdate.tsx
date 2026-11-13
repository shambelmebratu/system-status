'use client';

import { useState } from 'react';
import { useApp } from '../lib/app';
import type { Server } from '../lib/types';
import { JoinCommands, useActiveEnrollment, useControlPlaneUrl } from './join';
import { CodeBox, Icon } from './ui';

/** "Update available" banner for a server agent, with the command that fits how that agent is installed. */
export function AgentUpdate({ server, latest }: { server: Server; latest: string }) {
  const { canOperate } = useApp();
  const [open, setOpen] = useState(false);
  const [base] = useControlPlaneUrl();
  const kind = server.last_metrics?.install || 'systemd';
  const current = server.last_metrics?.agent_version;
  return (
    <section className="card update-card">
      <div className="update-head">
        <span className="kpi-ico"><Icon name="refresh" size={16} /></span>
        <div style={{ minWidth: 0 }}><b>Agent update available</b><div className="sm muted">v{current} → v{latest}</div></div>
        <span className="grow" />
        {canOperate && <button className="btn sm primary" onClick={() => setOpen(!open)}>{open ? 'Hide command' : 'Show update command'}</button>}
      </div>
      {open && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
          {kind === 'bundled' && <>
            <span className="sm muted">This is the agent bundled with SM-Watch. Run this in the folder that holds its <code>docker-compose.yml</code>:</span>
            <CodeBox value="docker compose pull host-agent && docker compose up -d host-agent" />
          </>}
          {kind === 'docker' && <DockerUpdate base={base} />}
          {(kind === 'systemd' || kind === 'macos') && <>
            <span className="sm muted">Run this on <b>{server.last_metrics?.hostname || server.name}</b>. The agent keeps its identity and settings; no install link is needed:</span>
            <CodeBox value={`curl -fsSL ${base}/api/agent/install.sh | sudo bash -s -- update`} />
          </>}
          <span className="sm muted">The agent restarts for a few seconds and reconnects by itself. This banner disappears once it reports the new version.</span>
        </div>)}
    </section>
  );
}

function DockerUpdate({ base }: { base: string }) {
  const enrollment = useActiveEnrollment();
  const e = enrollment.active;
  return (
    <>
      <span className="sm muted">This agent runs in Docker. Re-running the Docker install command pulls the new image and replaces the container; the agent keeps its identity.</span>
      {e ? <JoinCommands token={e.token} base={base} />
        : <div><button className="btn sm" disabled={enrollment.busy} onClick={() => void enrollment.generate('Agent update')}>Generate command</button> <span className="sm muted">(creates a short-lived install link)</span></div>}
    </>
  );
}

/** Same idea for the in-cluster agent. */
export function ClusterAgentUpdate({ current, latest }: { current: string | null; latest: string }) {
  const { canOperate } = useApp();
  const [open, setOpen] = useState(false);
  return (
    <section className="card update-card">
      <div className="update-head">
        <span className="kpi-ico"><Icon name="refresh" size={16} /></span>
        <div style={{ minWidth: 0 }}><b>Agent update available</b><div className="sm muted">v{current} → v{latest}</div></div>
        <span className="grow" />
        {canOperate && <button className="btn sm primary" onClick={() => setOpen(!open)}>{open ? 'Hide command' : 'Show update command'}</button>}
      </div>
      {open && <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
        <span className="sm muted">Run with the same kubeconfig you used to install it. It pulls the newest image and restarts the agent pod (its token and settings stay in the cluster Secret):</span>
        <CodeBox value="kubectl -n smwatch rollout restart deployment/smwatch-agent" />
        <span className="sm muted">If you pinned a version in the manifest, change the image tag there instead.</span>
      </div>}
    </section>
  );
}
