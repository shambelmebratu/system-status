'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, post } from '../lib/api';
import { Field } from './ui';

type Inventory = { files: string[]; journal: boolean; units: string[]; docker: boolean; containers: { name: string; state: string; image: string }[]; notes: string[] };
type Source = 'docker' | 'journal' | 'file';
type LogResponse = { id: number; status: 'pending' | 'running' | 'done' | 'error'; output: string; error: string | null; truncated: boolean };

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/** Queues a log request for the server's agent and waits for the answer (the agent polls every few seconds). */
async function runQuery(serverId: number, query: Record<string, unknown>, isCancelled: () => boolean): Promise<LogResponse> {
  const { id } = await post<{ id: number }>(`/servers/${serverId}/logs`, query);
  for (let i = 0; i < 80; i++) {
    await sleep(i < 10 ? 500 : 1000);
    if (isCancelled()) throw new Error('cancelled');
    const result = await api<LogResponse>(`/servers/${serverId}/logs/${id}`);
    if (result.status === 'done') return result;
    if (result.status === 'error') throw new Error(result.error || 'The agent could not read that log');
  }
  throw new Error('Timed out waiting for the agent');
}

const levelOf = (line: string) => (/\b(error|err|fatal|crit|critical|panic|emerg|exception|traceback|failed|denied)\b/i.test(line) ? 'bad' : /\b(warn|warning|timeout|retry|deprecated)\b/i.test(line) ? 'warn' : '');

export function LogsPanel({ serverId }: { serverId: number }) {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [source, setSource] = useState<Source>('docker');
  const [target, setTarget] = useState('');
  const [lines, setLines] = useState('200');
  const [since, setSince] = useState('0');
  const [grep, setGrep] = useState('');
  const [priority, setPriority] = useState('');
  const [output, setOutput] = useState<string | null>(null);
  const [meta, setMeta] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [auto, setAuto] = useState(false);
  const [wrap, setWrap] = useState(false);
  const run = useRef(0);
  const box = useRef<HTMLPreElement>(null);

  // What can this server's agent read?
  useEffect(() => {
    const mine = ++run.current;
    setInventory(null); setOutput(null); setError(''); setTarget('');
    runQuery(serverId, { source: 'inventory' }, () => run.current !== mine)
      .then(result => {
        const inv = JSON.parse(result.output) as Inventory;
        setInventory(inv);
        const first: Source = inv.docker && inv.containers.length ? 'docker' : inv.journal ? 'journal' : 'file';
        setSource(first);
        setTarget(first === 'docker' ? inv.containers[0].name : first === 'journal' ? 'all' : inv.files[0] ?? '');
      })
      .catch(e => (e as Error).message !== 'cancelled' && setError((e as Error).message));
    return () => { run.current++; };
  }, [serverId]);

  const fetchLogs = useCallback(async (quiet = false) => {
    if (!target) return;
    const mine = ++run.current;
    if (!quiet) setBusy(true);
    setError('');
    try {
      const result = await runQuery(serverId, { source, target, lines: Number(lines), since_minutes: Number(since), grep, priority: source === 'journal' ? priority : '' }, () => run.current !== mine);
      setOutput(result.output);
      setMeta(`${result.output ? result.output.split('\n').length : 0} lines${result.truncated ? ' (truncated to the newest 400 KB)' : ''} · fetched ${new Date().toLocaleTimeString()}`);
      requestAnimationFrame(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; });
    } catch (e) { if ((e as Error).message !== 'cancelled') setError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [serverId, source, target, lines, since, grep, priority]);

  useEffect(() => {
    if (!auto) return;
    const timer = setInterval(() => void fetchLogs(true), 6000);
    return () => clearInterval(timer);
  }, [auto, fetchLogs]);

  const targets = useMemo(() => {
    if (!inventory) return [] as { value: string; label: string }[];
    if (source === 'docker') return inventory.containers.map(c => ({ value: c.name, label: `${c.name}  (${c.state})` }));
    if (source === 'journal') return [{ value: 'all', label: 'All units (whole journal)' }, ...inventory.units.map(u => ({ value: u, label: u }))];
    return inventory.files.map(f => ({ value: f, label: f }));
  }, [inventory, source]);

  const pick = (next: Source) => {
    setSource(next); setOutput(null);
    setTarget(next === 'docker' ? inventory?.containers[0]?.name ?? '' : next === 'journal' ? 'all' : inventory?.files[0] ?? '');
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([output ?? ''], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = `${target.replace(/[^A-Za-z0-9_.-]+/g, '_') || 'logs'}.log`; a.click(); URL.revokeObjectURL(url);
  };

  if (error && !inventory) return <div className="card"><div className="err">{error}</div><p className="muted sm" style={{ marginTop: 10 }}>Logs need the SM-Watch agent (version 2.3+) running on the server with log access enabled. Re-run the install command on the server to update it.</p></div>;
  if (!inventory) return <div className="card"><div className="waiting"><span className="spinner" />Asking the agent which logs it can read…</div></div>;

  const available: [Source, string, boolean][] = [['docker', `Docker containers (${inventory.containers.length})`, inventory.docker], ['journal', 'System journal', inventory.journal], ['file', `Log files (${inventory.files.length})`, inventory.files.length > 0]];
  return (
    <div className="card">
      <div className="seg" style={{ marginBottom: 14, flexWrap: 'wrap' }}>
        {available.map(([id, label, ok]) => <button key={id} className={source === id ? 'on' : ''} disabled={!ok} title={ok ? '' : 'Not available on this server'} style={ok ? undefined : { opacity: 0.4 }} onClick={() => pick(id)}>{label}</button>)}
      </div>
      {inventory.notes.length > 0 && <p className="muted sm" style={{ marginBottom: 12 }}>{inventory.notes.join(' · ')}</p>}
      <form className="form-grid" style={{ alignItems: 'end', marginBottom: 14 }} onSubmit={e => { e.preventDefault(); void fetchLogs(); }}>
        <Field label={source === 'docker' ? 'Container' : source === 'journal' ? 'Unit' : 'File'}>
          <select value={target} onChange={e => setTarget(e.target.value)}>{targets.length === 0 && <option value="">Nothing available</option>}{targets.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}</select>
        </Field>
        <Field label="Filter (contains)"><input value={grep} onChange={e => setGrep(e.target.value)} placeholder="e.g. error, 502, GET /api" maxLength={200} /></Field>
        <Field label="Lines"><select value={lines} onChange={e => setLines(e.target.value)}>{['100', '200', '500', '1000', '2000'].map(n => <option key={n} value={n}>last {n}</option>)}</select></Field>
        {source !== 'file' && <Field label="Time"><select value={since} onChange={e => setSince(e.target.value)}><option value="0">any time</option><option value="15">last 15 min</option><option value="60">last hour</option><option value="360">last 6 hours</option><option value="1440">last 24 hours</option><option value="10080">last 7 days</option></select></Field>}
        {source === 'journal' && <Field label="Minimum level"><select value={priority} onChange={e => setPriority(e.target.value)}><option value="">all</option><option value="err">errors</option><option value="warning">warnings +</option><option value="notice">notices +</option><option value="info">info +</option></select></Field>}
        <button className="btn primary" disabled={busy || !target}>{busy ? 'Fetching…' : 'Show logs'}</button>
      </form>
      {error && <div className="err" style={{ marginBottom: 12 }}>{error}</div>}
      {output !== null && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
            <span className="muted sm">{meta}</span><span style={{ flex: 1 }} />
            <label className="check"><input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)} />Auto-refresh</label>
            <label className="check"><input type="checkbox" checked={wrap} onChange={e => setWrap(e.target.checked)} />Wrap</label>
            <button className="btn sm" onClick={() => void navigator.clipboard?.writeText(output)}>Copy</button>
            <button className="btn sm" onClick={download}>Download</button>
          </div>
          <pre ref={box} className="logbox" style={{ whiteSpace: wrap ? 'pre-wrap' : 'pre' }}>
            {output === '' ? <span className="muted">No matching log lines.</span> : output.split('\n').map((line, i) => <span key={i} className={levelOf(line)}>{line}{'\n'}</span>)}
          </pre>
        </>
      )}
    </div>
  );
}
