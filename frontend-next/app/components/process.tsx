'use client';

import { useCallback, useEffect, useState } from 'react';
import { Icon } from './ui';
import { api, post } from '../lib/api';
import { duration } from '../lib/format';

type Proc = {
  pid: number; ppid: number; name: string; status: string; user: string | null; uid: number | null; gid: number | null; group: string | null; started: string; elapsed_seconds: number;
  cpu_percent: number | null; memory_percent: number | null; rss_bytes: number | null; threads: number | null; nice: number | null; fds: number | null; terminal: string | null;
  cmdline: string; exe: string | null; cwd: string | null; environment: { name: string; value: string | null }[]; cgroup: string | null;
  container: { id: string; runtime: string; name?: string; image?: string; kubernetes?: boolean } | null; proc_status: Record<string, string>;
  parent: { pid: number; name: string; cmdline: string } | null; children: { pid: number; name: string }[];
  connections: { status: string; local: string; remote: string }[] | null; flags: { severity: string; kind: string; reason: string }[];
};

const mb = (n: number | null | undefined) => (n == null ? '–' : n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(2)} GB` : `${Math.round(n / 1024 ** 2)} MB`);

/** One process, looked up live by the agent: what it is, who runs it, where it came from, what it is connected to. */
export function ProcessDrawer({ serverId, pid, name, onClose }: { serverId: number; pid: number; name?: string; onClose: () => void }) {
  const [current, setCurrent] = useState(pid);
  const [proc, setProc] = useState<Proc | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [showEnv, setShowEnv] = useState(false);
  const load = useCallback(async (target: number) => {
    setBusy(true); setError(''); setProc(null);
    try {
      const { id } = await post<{ id: number }>(`/servers/${serverId}/processes/${target}`);
      for (let i = 0; i < 4; i++) {
        const r = await api<{ status: string; output: string; error: string | null }>(`/servers/${serverId}/logs/${id}?wait=15`);
        if (r.status === 'done') { setProc(JSON.parse(r.output)); return; }
        if (r.status === 'error') { setError(r.error ?? 'The agent could not inspect this process'); return; }
      }
      setError('The agent did not answer in time.');
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }, [serverId]);
  useEffect(() => { void load(current); }, [current, load]);
  useEffect(() => { const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [onClose]);
  const p = proc;
  const st = p?.proc_status ?? {};
  return (
    <div className="drawer-overlay" onMouseDown={e => e.target === e.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Process ${current}`}>
        <div className="drawer-head"><div style={{ minWidth: 0 }}><div className="sm muted">Process · PID {current}</div><h2 className="trunc">{p?.name ?? name ?? '…'}</h2></div><span className="grow" />
          <button className="btn ghost sm" onClick={() => void load(current)} disabled={busy} title="Look again"><Icon name="refresh" size={14} /></button>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button></div>
        <div className="drawer-body">
          {busy && <p className="muted"><span className="spinner" /> Asking the agent…</p>}
          {error && <div className="err">{error}</div>}
          {p && <>
            {p.flags.length > 0 && <div className="proc-flags">{p.flags.map((f, i) => <div key={i} className={`proc-flag ${f.severity}`}><Icon name="alert" size={14} /><span>This process {f.reason}.</span></div>)}</div>}
            <div className="facts proc-facts">
              <div><small>User</small><b>{p.user ?? p.uid ?? '–'}</b>{p.group && <span className="muted sm">group {p.group}</span>}</div>
              <div><small>State</small><b>{p.status}</b></div>
              <div><small>Running for</small><b>{duration(p.elapsed_seconds)}</b><span className="muted sm">since {new Date(p.started).toLocaleString()}</span></div>
              <div><small>CPU</small><b>{p.cpu_percent ?? '–'}%</b></div>
              <div><small>Memory</small><b>{mb(p.rss_bytes)}</b><span className="muted sm">{p.memory_percent ?? '–'}% of RAM</span></div>
              <div><small>Threads</small><b>{p.threads ?? st.Threads ?? '–'}</b>{p.fds != null && <span className="muted sm">{p.fds} open files</span>}</div>
            </div>
            <h3 className="drawer-h">Command</h3>
            <code className="proc-cmd">{p.cmdline || `[${p.name}]`}</code>
            <dl className="proc-dl">
              <dt>Program</dt><dd className="mono">{p.exe ?? <span className="muted">not readable</span>}{p.exe?.endsWith(' (deleted)') && <span className="tag warn" style={{ marginLeft: 6 }}>deleted from disk</span>}</dd>
              <dt>Working folder</dt><dd className="mono">{p.cwd ?? <span className="muted">not readable</span>}</dd>
              <dt>Parent</dt><dd>{p.parent ? <button className="lg-link" onClick={() => setCurrent(p.parent!.pid)}>{p.parent.name} (PID {p.parent.pid})</button> : `PID ${p.ppid}`}{p.parent?.cmdline && <div className="muted sm mono trunc">{p.parent.cmdline}</div>}</dd>
              {p.container && <><dt>Container</dt><dd>{p.container.name ? <b>{p.container.name}</b> : null} <span className="mono sm">{p.container.id}</span> <span className="muted sm">{p.container.runtime}{p.container.kubernetes ? ' · Kubernetes' : ''}</span>{p.container.image && <div className="muted sm mono">{p.container.image}</div>}</dd></>}
              {p.cgroup && <><dt>Control group</dt><dd className="mono sm trunc" title={p.cgroup}>{p.cgroup}</dd></>}
              {p.terminal && <><dt>Terminal</dt><dd className="mono">{p.terminal}</dd></>}
            </dl>
            {p.children.length > 0 && <><h3 className="drawer-h">Started by it ({p.children.length})</h3><div className="chips">{p.children.map(c => <button key={c.pid} className="chip" onClick={() => setCurrent(c.pid)}>{c.name} <span className="muted">{c.pid}</span></button>)}</div></>}
            {p.connections && p.connections.length > 0 && <><h3 className="drawer-h">Network</h3><table className="tbl"><tbody>{p.connections.map((c, i) => <tr key={i}><td className="sm">{c.status === 'LISTEN' ? 'listening' : c.status.toLowerCase()}</td><td className="mono sm">{c.local}</td><td className="mono sm">{c.remote ? `→ ${c.remote}` : ''}</td></tr>)}</tbody></table></>}
            {Object.keys(st).length > 0 && <h3 className="drawer-h">Kernel status</h3>}
            <div className="chips">{Object.entries(st).filter(([k]) => ['VmRSS', 'VmSize', 'VmSwap', 'Threads', 'voluntary_ctxt_switches', 'Seccomp', 'NoNewPrivs'].includes(k)).map(([k, v]) => <span key={k} className="chip"><span className="muted">{k}</span> {v}</span>)}</div>
            <h3 className="drawer-h">Environment {p.environment.length ? <><span className="muted sm">({p.environment.length} variables)</span> <button className="lg-link" onClick={() => setShowEnv(!showEnv)}>{showEnv ? 'hide' : 'show names'}</button></> : <span className="muted sm">not readable by the agent</span>}</h3>
            {showEnv && <><p className="muted sm">Values are not sent by the agent (they often hold passwords and keys), except harmless ones such as PATH and HOME.</p>
              <table className="tbl"><tbody>{p.environment.map(e => <tr key={e.name}><td className="mono sm">{e.name}</td><td className="mono sm trunc">{e.value ?? <span className="muted">hidden</span>}</td></tr>)}</tbody></table></>}
          </>}
        </div>
      </aside>
    </div>
  );
}
