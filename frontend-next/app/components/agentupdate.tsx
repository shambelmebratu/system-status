'use client';

import { useState } from 'react';
import { useApp } from '../lib/app';
import type { Server } from '../lib/types';
import { useControlPlaneUrl } from './join';
import { CodeBox, Icon } from './ui';

/** "Update available" banner for a server agent, with the command that fits how that agent is installed. */
type Kind = 'systemd' | 'macos' | 'docker' | 'bundled';
const KIND_LABEL: Record<Kind, string> = { systemd: 'Linux service', macos: 'macOS service', docker: 'Docker container', bundled: 'Bundled with SM-Watch' };

function UpdateCommand({ kind, base, hostname }: { kind: Kind; base: string; hostname: string }) {
  if (kind === 'bundled') return <>
    <span className="sm muted">This is the agent bundled with SM-Watch. Run this in the folder that holds its <code>docker-compose.yml</code>:</span>
    <CodeBox value="docker compose pull host-agent && docker compose up -d host-agent" />
  </>;
  if (kind === 'docker') return <>
    <span className="sm muted">Run this on <b>{hostname}</b>. It pulls the new image and recreates the container with its current settings; the agent keeps its identity. No link or token needed:</span>
    <CodeBox value={`curl -fsSL ${base}/api/agent/docker-update.sh | sudo bash`} />
  </>;
  return <>
    <span className="sm muted">Run this on <b>{hostname}</b>. The agent keeps its identity and settings; no install link is needed:</span>
    <CodeBox value={`curl -fsSL ${base}/api/agent/install.sh | sudo bash -s -- update`} />
  </>;
}

/** "Update available" banner for a server agent, with the command that fits how that agent is installed. */
export function AgentUpdate({ server, latest }: { server: Server; latest: string }) {
  const { canOperate } = useApp();
  const [open, setOpen] = useState(false);
  const [base] = useControlPlaneUrl();
  const reported = server.last_metrics?.install as Kind | '' | undefined;
  const [picked, setPicked] = useState<Kind>('docker');
  const current = server.last_metrics?.agent_version;
  const hostname = server.last_metrics?.hostname || server.name;
  const kind: Kind = reported || picked;
  return (
    <section className="card update-card">
      <div className="update-head">
        <span className="kpi-ico"><Icon name="refresh" size={16} /></span>
        <div style={{ minWidth: 0 }}><b>Agent update available</b><div className="sm muted">v{current} → v{latest}{reported ? ` · ${KIND_LABEL[reported]}` : ''}</div></div>
        <span className="grow" />
        {canOperate && <button className="btn sm primary" onClick={() => setOpen(!open)}>{open ? 'Hide command' : 'Show update command'}</button>}
      </div>
      {open && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
          {!reported && <>
            <span className="sm muted">This agent is too old to say how it was installed. Pick the one that matches (after this update it will report it by itself):</span>
            <div className="seg" style={{ alignSelf: 'flex-start' }}>{(['docker', 'systemd', 'bundled'] as Kind[]).map(k => <button key={k} className={picked === k ? 'on' : ''} onClick={() => setPicked(k)}>{KIND_LABEL[k]}</button>)}</div>
          </>}
          <UpdateCommand kind={kind} base={base} hostname={hostname} />
          <span className="sm muted">The agent restarts for a few seconds and reconnects by itself. This banner disappears once it reports the new version.</span>
        </div>)}
    </section>
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
