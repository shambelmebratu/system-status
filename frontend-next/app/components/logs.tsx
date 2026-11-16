'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, post } from '../lib/api';
import { Icon } from './ui';
import { LogViewer, LogPalette, TargetPicker, type LogFetch, type PickerOption, type PaletteGroup } from './logviewer';

type Inventory = { files: string[]; journal: boolean; journal_all?: boolean; journal_label?: string; platform?: string; units: string[]; docker: boolean; containers: { name: string; state: string; image: string }[]; notes: string[] };
type Source = 'docker' | 'journal' | 'file';
type LogResponse = { id: number; status: 'pending' | 'running' | 'done' | 'error'; output: string; error: string | null; truncated: boolean };


const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/** Queues a log request and waits for the agent's answer. The server holds each GET open until the agent has answered
 *  (long-poll), so the result appears the instant it exists instead of on the next polling tick. */
export async function runQuery(serverId: number, query: Record<string, unknown>, isCancelled: () => boolean): Promise<LogResponse> {
  const { id } = await post<{ id: number }>(`/servers/${serverId}/logs`, query);
  const deadline = Date.now() + 50_000;
  while (Date.now() < deadline) {
    if (isCancelled()) throw new Error('cancelled');
    const result = await api<LogResponse>(`/servers/${serverId}/logs/${id}?wait=15`);
    if (result.status === 'done') return result;
    if (result.status === 'error') throw new Error(result.error || 'The agent could not read that log');
  }
  throw new Error('Timed out waiting for the agent');
}

/** The last source/target viewed on each server is remembered so the next visit can start fetching immediately. */
type Remembered = { source: Source; target: string };
const memKey = (serverId: number) => `smw_logs_last_${serverId}`;
function readLast(serverId: number): Remembered | null {
  try {
    const v = JSON.parse(localStorage.getItem(memKey(serverId)) || 'null');
    return v && ['docker', 'journal', 'file'].includes(v.source) && typeof v.target === 'string' && v.target ? v : null;
  } catch { return null; }
}
function writeLast(serverId: number, value: Remembered) { try { localStorage.setItem(memKey(serverId), JSON.stringify(value)); } catch { /* storage unavailable */ } }
const EMPTY_INVENTORY: Inventory = { files: [], journal: true, units: [], docker: true, containers: [], notes: [] };

const SOURCES: { id: Source; label: string; icon: string }[] = [{ id: 'docker', label: 'Containers', icon: 'server' }, { id: 'journal', label: 'System journal', icon: 'logs' }, { id: 'file', label: 'Log files', icon: 'overview' }];
const isMac = (inv: { platform?: string }) => inv.platform === 'macos';

export function LogsPanel({ serverId }: { serverId: number }) {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [unitsState, setUnitsState] = useState<'idle' | 'loading' | 'done'>('idle');
  const [provisional, setProvisional] = useState<Remembered | null>(null);
  const [source, setSource] = useState<Source>('docker');
  const [target, setTarget] = useState('');
  const [error, setError] = useState('');
  const invRun = useRef(0);    // newest inventory request
  const [paletteOpen, setPaletteOpen] = useState(false);
  useEffect(() => { const k = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen(o => !o); } }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, []);

  // What can this server's agent read? A remembered last view is shown at once, in parallel with the inventory request.
  useEffect(() => {
    const mine = ++invRun.current;
    setInventory(null); setUnitsState('idle'); setError(''); setTarget('');
    const remembered = readLast(serverId);
    setProvisional(remembered);
    if (remembered) { setSource(remembered.source); setTarget(remembered.target); }
    runQuery(serverId, { source: 'inventory' }, () => invRun.current !== mine)
      .then(result => {
        const inv = JSON.parse(result.output) as Inventory;
        setInventory(inv); setProvisional(null);
        const stillValid = remembered && (remembered.source === 'docker' ? inv.containers.some(c => c.name === remembered.target)
          : remembered.source === 'journal' ? inv.journal : inv.files.includes(remembered.target));
        if (stillValid) return;
        const src: Source = inv.docker && inv.containers.length ? 'docker' : inv.journal ? 'journal' : 'file';
        const tgt = src === 'docker' ? (inv.containers.find(c => c.state === 'running') ?? inv.containers[0]).name : src === 'journal' ? 'all' : inv.files[0] ?? '';   // prefer a container that is actually running
        setSource(src); setTarget(tgt);
      })
      .catch(e => (e as Error).message !== 'cancelled' && setError((e as Error).message));
    return () => { invRun.current++; };
  }, [serverId]);

  // The unit list needs a slow journal scan on the server, so it is only requested when the journal tab is opened.
  const loadUnits = useCallback(() => {
    if (unitsState !== 'idle') return;
    setUnitsState('loading');
    const mine = invRun.current;
    runQuery(serverId, { source: 'inventory', target: 'units' }, () => invRun.current !== mine)
      .then(result => { const { units } = JSON.parse(result.output) as { units: string[] }; setInventory(inv => (inv ? { ...inv, units } : inv)); setUnitsState('done'); })
      .catch(() => setUnitsState('idle'));
  }, [serverId, unitsState]);

  // Until the real inventory arrives, a remembered last view is shown with just that one target.
  const shell = inventory ?? (provisional ? { ...EMPTY_INVENTORY, containers: provisional.source === 'docker' ? [{ name: provisional.target, state: 'running', image: '' }] : [], files: provisional.source === 'file' ? [provisional.target] : [] } : null);
  const targets = useMemo<PickerOption[]>(() => {
    if (!shell) return [];
    if (source === 'docker') return [...shell.containers].sort((a, b) => Number(b.state === 'running') - Number(a.state === 'running')).map(c => ({ value: c.name, label: c.name, dot: c.state, hint: c.state !== 'running' ? c.state : c.image.split('/').pop() }));
    if (source === 'journal') return [...(shell.journal_all === false ? [] : [{ value: 'all', label: isMac(shell) ? 'Whole system log' : 'Whole journal (all units)' }]), ...shell.units.map(u => ({ value: u, label: u }))];
    return shell.files.map(f => ({ value: f, label: f.replace(/^\/var\/log\//, ''), hint: f.startsWith('/var/log/') ? '/var/log' : undefined }));
  }, [shell, source]);

  useEffect(() => {
    if (source === 'journal' && !target && unitsState === 'done' && inventory && inventory.units.length) setTarget(inventory.units[0]);
  }, [unitsState, source, target, inventory]);

  const pick = (next: Source) => {
    if (next === source) return;
    const tgt = next === 'docker' ? (inventory?.containers.find(c => c.state === 'running') ?? inventory?.containers[0])?.name ?? '' : next === 'journal' ? (inventory?.journal_all === false ? '' : 'all') : inventory?.files[0] ?? '';
    setSource(next); setTarget(tgt);
    if (next === 'journal') loadUnits();
  };

  const fetcher: LogFetch = useCallback(async (q, cancelled) => {
    const result = await runQuery(serverId, { source, target, lines: q.lines, since_seconds: q.sinceSeconds, grep: q.grep, priority: '' }, cancelled);
    writeLast(serverId, { source, target });
    return { text: result.output, truncated: result.truncated };
  }, [serverId, source, target]);

  if (error && !shell) return (
    <div className="lg"><div className="lg-empty"><Icon name="alert" size={28} /><h3>Can’t reach this server’s agent</h3><p>{error}</p>
      <p className="muted sm">Logs need the SM-Watch agent (2.3+) running on the server with log access enabled. Re-run the install command on the server to update it.</p></div></div>);
  if (!shell) return (
    <div className="lg"><div className="lg-skel">{Array.from({ length: 9 }, (_, i) => <i key={i} style={{ width: `${40 + ((i * 37) % 55)}%` }} />)}</div>
      <div className="lg-foot"><span className="spinner" /> Asking the agent which logs it can read…</div></div>);

  const switchTo = (src: Source) => (value: string) => { setSource(src); setTarget(value); if (src === 'journal') loadUnits(); };
  const groups: PaletteGroup[] = [
    { label: 'Containers', icon: 'server', onPick: switchTo('docker'), options: shell.containers.map(c => ({ value: c.name, label: c.name, dot: c.state, hint: c.state !== 'running' ? c.state : c.image.split('/').pop() })) },
    { label: shell.journal_label || 'System journal', icon: 'logs', onPick: switchTo('journal'), options: shell.journal ? [...(shell.journal_all === false ? [] : [{ value: 'all', label: 'Whole journal' }]), ...shell.units.map(u => ({ value: u, label: u }))] : [] },
    { label: 'Log files', icon: 'overview', onPick: switchTo('file'), options: shell.files.map(f => ({ value: f, label: f.replace(/^\/var\/log\//, '') })) },
  ].filter(g => g.options.length > 0);
  const available: Record<Source, boolean> = { docker: shell.docker && shell.containers.length > 0, journal: shell.journal, file: shell.files.length > 0 };
  const total: Record<Source, string> = { docker: String(shell.containers.length), journal: unitsState === 'done' ? String(shell.units.length) : '–', file: String(shell.files.length) };
  const noteFor = (id: Source) => (id === 'journal' ? shell.notes.find(n => /journal|systemd|macOS/i.test(n)) : id === 'file' ? shell.notes.find(n => /log files/i.test(n)) : shell.notes.find(n => /docker/i.test(n))) ?? shell.notes[0] ?? 'Not available on this server';
  const controls = (
    <>
      <div className="lg-sources" role="tablist">
        {SOURCES.map(s => (
          <button key={s.id} role="tab" aria-selected={source === s.id} className={source === s.id ? 'on' : ''} disabled={!available[s.id]} title={available[s.id] ? '' : noteFor(s.id)} onClick={() => pick(s.id)}>
            <Icon name={s.icon} size={15} />{s.id === 'journal' && shell.journal_label ? shell.journal_label : s.label}<span className="lg-count">{total[s.id]}</span>
          </button>))}
      </div>
      <TargetPicker value={target} options={targets} onChange={setTarget} icon={source === 'docker' ? 'server' : source === 'journal' ? 'logs' : 'overview'} width={340}
        placeholder={source === 'journal' && unitsState !== 'done' ? 'Loading units…' : 'Nothing available'} disabled={targets.length === 0} />
      <button type="button" className="btn ghost sm" onClick={() => setPaletteOpen(true)} title="Switch to any container, unit or file"><kbd>⌘K</kbd> Switch log</button>
    </>
  );
  const banner = shell.notes.length > 0 ? <div className="lv-note">{shell.notes.map((n, i) => <p key={i}><Icon name="alert" size={14} />{n}</p>)}</div> : null;
  return <><LogPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} groups={groups} title="Switch log: container, unit or file…" /><LogViewer fetcher={fetcher} fetchKey={`${serverId}|${source}|${target}`} canFetch={!!target} controls={controls} banner={banner} storageKey={`server-${serverId}`} downloadName={target || 'logs'} /></>;
}
