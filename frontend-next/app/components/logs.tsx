'use client';

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, post } from '../lib/api';
import { Icon } from './ui';

type Inventory = { files: string[]; journal: boolean; journal_all?: boolean; journal_label?: string; platform?: string; units: string[]; docker: boolean; containers: { name: string; state: string; image: string }[]; notes: string[] };
type Source = 'docker' | 'journal' | 'file';
type LogResponse = { id: number; status: 'pending' | 'running' | 'done' | 'error'; output: string; error: string | null; truncated: boolean };
export type Level = 'error' | 'warn' | 'info' | 'debug' | '';
export type Row = { n: number; ts: string; tsTitle: string; level: Level; msg: string };

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/** Queues a log request and waits for the agent's answer. The server holds each GET open until the agent has answered
 *  (long-poll), so the result appears the instant it exists instead of on the next polling tick. */
async function runQuery(serverId: number, query: Record<string, unknown>, isCancelled: () => boolean): Promise<LogResponse> {
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

/* ---------------------------------------------------------------- parsing */
const TS_PREFIX = [
  /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+/,   // docker, journald short-iso, app logs
  /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})\s+/,                                         // nginx error log
  /^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+/,                                     // classic syslog
];
const NGINX_TS = /\[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]/;
const NGINX_STATUS = /"\s*(?:[A-Z]+) [^"]*"\s+(\d{3})\s/;
const MONTHS: Record<string, string> = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };
const ERR = /\b(error|err|fatal|crit(?:ical)?|panic|emerg|alert|exception|traceback|failed|failure|denied|refused|segfault|oom)\b/i;
const WARN = /\b(warn(?:ing)?|timeout|timed out|retry(?:ing)?|deprecated|slow)\b/i;
const DBG = /\b(debug|trace)\b/i;
const INF = /\b(info|notice)\b/i;

function when(raw: string): { ts: string; title: string } {
  let iso = raw.replace(' ', 'T').replace(',', '.').replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  if (/^\d{4}\/\d{2}\/\d{2}/.test(raw)) iso = raw.replace(/\//g, '-').replace(' ', 'T');
  const date = new Date(iso);
  if (!isNaN(date.getTime())) return { ts: date.toLocaleTimeString([], { hour12: false }), title: date.toLocaleString() };
  return { ts: raw, title: raw };
}

export function parse(output: string): Row[] {
  return output.split('\n').filter(l => l.length).map((line, i) => {
    let ts = '', title = '', msg = line;
    for (const rx of TS_PREFIX) {
      const m = rx.exec(line);
      if (m) { ({ ts, title } = when(m[1])); msg = line.slice(m[0].length); break; }
    }
    if (!ts) {
      const nx = NGINX_TS.exec(line);
      if (nx) { ({ ts, title } = when(`${nx[3]}-${MONTHS[nx[2]] ?? '01'}-${nx[1]}T${nx[4]}${nx[5].slice(0, 3)}:${nx[5].slice(3)}`)); }
    }
    // HTTP access logs: the status code decides (5xx error, 4xx warning). Everything else is judged by its wording.
    const status = NGINX_STATUS.exec(line);
    let level: Level = status && status[1][0] === '5' ? 'error' : status && status[1][0] === '4' ? 'warn' : '';
    if (!level) level = ERR.test(msg) ? 'error' : WARN.test(msg) ? 'warn' : DBG.test(msg) ? 'debug' : INF.test(msg) ? 'info' : '';
    // The badge already says it, so drop a leading "INFO:" / "ERROR " token from the text.
    const lead = /^\[?(INFO|WARN(?:ING)?|ERROR|ERR|DEBUG|NOTICE|CRITICAL|FATAL)\]?[:\s]+/i.exec(msg);
    if (lead && level) msg = msg.slice(lead[0].length);
    return { n: i + 1, ts, tsTitle: title, level, msg };
  });
}

const escapeRx = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export function Highlight({ text, term }: { text: string; term: string }) {
  if (!term) return <>{text}</>;
  const parts = text.split(new RegExp(`(${escapeRx(term)})`, 'ig'));
  return <>{parts.map((p, i) => (i % 2 ? <mark key={i}>{p}</mark> : <Fragment key={i}>{p}</Fragment>))}</>;
}

export const LEVEL_LABEL: Record<string, string> = { error: 'ERR', warn: 'WARN', info: 'INFO', debug: 'DBG' };
const SOURCES: { id: Source; label: string; icon: string }[] = [{ id: 'docker', label: 'Containers', icon: 'server' }, { id: 'journal', label: 'System journal', icon: 'logs' }, { id: 'file', label: 'Log files', icon: 'overview' }];
const isMac = (inv: { platform?: string }) => inv.platform === 'macos';

export function LogsPanel({ serverId }: { serverId: number }) {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [unitsState, setUnitsState] = useState<'idle' | 'loading' | 'done'>('idle');
  const [provisional, setProvisional] = useState<Remembered | null>(null);
  const [source, setSource] = useState<Source>('docker');
  const [target, setTarget] = useState('');
  const [lines, setLines] = useState('200');
  const [since, setSince] = useState('0');
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState('');
  const [levelFilter, setLevelFilter] = useState<'all' | 'error' | 'warn'>('all');
  const [output, setOutput] = useState<string | null>(null);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);
  const [took, setTook] = useState(0);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState(false);
  const [wrap, setWrap] = useState(false);
  const [stuck, setStuck] = useState(true);
  const run = useRef(0);       // newest log request (older ones are ignored)
  const invRun = useRef(0);    // newest inventory request
  const scroller = useRef<HTMLDivElement>(null);
  const first = useRef(true);

  const fetchLogs = useCallback(async (opts: { quiet?: boolean; src?: Source; tgt?: string; filter?: string } = {}) => {
    const src = opts.src ?? source, tgt = opts.tgt ?? target;
    if (!tgt) return;
    const filter = opts.filter ?? search;
    const mine = ++run.current;
    const started = performance.now();
    if (!opts.quiet) setBusy(true);
    setError('');
    try {
      const result = await runQuery(serverId, { source: src, target: tgt, lines: Number(lines), since_minutes: src === 'file' ? 0 : Number(since), grep: filter, priority: '' }, () => run.current !== mine);
      setOutput(result.output); setTruncated(result.truncated); setApplied(filter); setFetchedAt(new Date()); setTook((performance.now() - started) / 1000);
      writeLast(serverId, { source: src, target: tgt });
    } catch (e) { if ((e as Error).message !== 'cancelled') setError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [serverId, source, target, lines, since, search]);

  // What can this server's agent read? If we remember what was open last time, start fetching THAT log right away, in
  // parallel with the inventory request, instead of waiting for the inventory first.
  useEffect(() => {
    const mine = ++invRun.current;
    setInventory(null); setUnitsState('idle'); setOutput(null); setError(''); setTarget('');
    const remembered = readLast(serverId);
    setProvisional(remembered);
    if (remembered) { setSource(remembered.source); setTarget(remembered.target); void fetchLogs({ src: remembered.source, tgt: remembered.target, filter: '' }); }
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
        if (tgt) void fetchLogs({ src, tgt, filter: '' });
      })
      .catch(e => (e as Error).message !== 'cancelled' && setError((e as Error).message));
    return () => { invRun.current++; run.current++; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  useEffect(() => { if (!live) return; const t = setInterval(() => void fetchLogs({ quiet: true }), 5000); return () => clearInterval(t); }, [live, fetchLogs]);

  const rows = useMemo(() => (output ? parse(output) : []), [output]);
  const counts = useMemo(() => ({ error: rows.filter(r => r.level === 'error').length, warn: rows.filter(r => r.level === 'warn').length }), [rows]);
  const shown = useMemo(() => rows.filter(r => levelFilter === 'all' || r.level === levelFilter), [rows, levelFilter]);

  // Keep following the newest lines (like `tail -f`) unless the user scrolled up.
  useEffect(() => { const el = scroller.current; if (el && stuck) el.scrollTop = el.scrollHeight; }, [shown, stuck]);
  const onScroll = () => { const el = scroller.current; if (el) setStuck(el.scrollHeight - el.scrollTop - el.clientHeight < 40); };

  // Until the real inventory arrives, a remembered last view is shown with just that one target (so its logs can appear at once).
  const shell = inventory ?? (provisional ? { ...EMPTY_INVENTORY, containers: provisional.source === 'docker' ? [{ name: provisional.target, state: 'running', image: '' }] : [], files: provisional.source === 'file' ? [provisional.target] : [] } : null);
  const targets = useMemo(() => {
    if (!shell) return [] as { value: string; label: string; dot?: string }[];
    if (source === 'docker') return [...shell.containers].sort((a, b) => Number(b.state === 'running') - Number(a.state === 'running')).map(c => ({ value: c.name, label: c.name, dot: c.state }));   // running containers first
    if (source === 'journal') return [...(shell.journal_all === false ? [] : [{ value: 'all', label: isMac(shell) ? 'Whole system log (last hour by default)' : 'Whole journal (all units)' }]), ...shell.units.map(u => ({ value: u, label: u }))];
    return shell.files.map(f => ({ value: f, label: f }));
  }, [shell, source]);

  useEffect(() => {
    if (source === 'journal' && !target && unitsState === 'done' && inventory && inventory.units.length) { setTarget(inventory.units[0]); void fetchLogs({ src: 'journal', tgt: inventory.units[0] }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unitsState, source, target]);

  const pick = (next: Source) => {
    if (next === source) return;
    const tgt = next === 'docker' ? (inventory?.containers.find(c => c.state === 'running') ?? inventory?.containers[0])?.name ?? '' : next === 'journal' ? 'all' : inventory?.files[0] ?? '';
    if (next === 'journal' && inventory?.journal_all === false) {   // the policy forbids the whole journal: choose a unit once the list is loaded
      setSource(next); setTarget(''); setOutput(null); setLive(false); loadUnits(); return;
    }
    setSource(next); setTarget(tgt); setOutput(null); setLive(false);
    void fetchLogs({ src: next, tgt });
    if (next === 'journal') loadUnits();
  };
  const changeTarget = (tgt: string) => { setTarget(tgt); setOutput(null); void fetchLogs({ tgt }); };
  const download = () => {
    const url = URL.createObjectURL(new Blob([output ?? ''], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = `${target.replace(/[^A-Za-z0-9_.-]+/g, '_') || 'logs'}.log`; a.click(); URL.revokeObjectURL(url);
  };

  if (error && !shell) return (
    <div className="lv"><div className="lv-empty"><Icon name="alert" size={26} /><h3>Can’t reach this server’s agent</h3><p>{error}</p>
      <p className="muted sm">Logs need the SM-Watch agent (2.3+) running on the server with log access enabled. Re-run the install command on the server to update it.</p></div></div>);
  if (!shell) return (
    <div className="lv"><div className="lv-skel">{Array.from({ length: 9 }, (_, i) => <i key={i} style={{ width: `${40 + ((i * 37) % 55)}%` }} />)}</div>
      <div className="lv-foot"><span className="spinner" /> Asking the agent which logs it can read…</div></div>);

  const available: Record<Source, boolean> = { docker: shell.docker && shell.containers.length > 0, journal: shell.journal, file: shell.files.length > 0 };
  const total: Record<Source, string> = { docker: inventory ? String(shell.containers.length) : '…', journal: unitsState === 'done' ? String(shell.units.length) : '–', file: inventory ? String(shell.files.length) : '…' };
  return (
    <div className="lv">
      <div className="lv-head">
        <div className="lv-tabs" role="tablist">
          {SOURCES.map(s => (
            <button key={s.id} role="tab" aria-selected={source === s.id} className={source === s.id ? 'on' : ''} disabled={!available[s.id]} title={available[s.id] ? '' : (s.id === 'journal' ? shell.notes.find(n => /journal|systemd|macOS/i.test(n)) : s.id === 'file' ? shell.notes.find(n => /log files/i.test(n)) : shell.notes.find(n => /docker/i.test(n))) ?? shell.notes[0] ?? 'Not available on this server'} onClick={() => pick(s.id)}>
              <Icon name={s.icon} size={15} />{s.id === 'journal' && shell.journal_label ? shell.journal_label : s.label}<span className="lv-count">{total[s.id]}</span>
            </button>))}
        </div>
        <span className="grow" />
        <button className={`lv-live ${live ? 'on' : ''}`} onClick={() => setLive(!live)} aria-pressed={live} title="Refresh every 5 seconds"><i />{live ? 'Live' : 'Live off'}</button>
        <button className="btn sm" onClick={() => void fetchLogs()} disabled={busy || !target}><Icon name="refresh" size={14} />{busy ? 'Loading…' : 'Refresh'}</button>
      </div>

      <form className="lv-filters" onSubmit={e => { e.preventDefault(); void fetchLogs({ filter: search }); }}>
        <label className="lv-target"><span className="lv-dot" data-state={targets.find(t => t.value === target)?.dot ?? ''} />
          <select value={target} onChange={e => changeTarget(e.target.value)} aria-label={source === 'docker' ? 'Container' : source === 'journal' ? 'Unit' : 'File'}>
            {targets.length === 0 && <option value="">Nothing available</option>}{targets.map(t => <option key={t.value} value={t.value}>{t.label}{t.dot && t.dot !== 'running' ? `  (${t.dot})` : ''}</option>)}</select></label>
        <label className="lv-search"><Icon name="logs" size={15} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search in logs…  (press Enter)" maxLength={200} aria-label="Search" />
          {(search || applied) && <button type="button" aria-label="Clear search" onClick={() => { setSearch(''); if (applied) void fetchLogs({ filter: '' }); }}><Icon name="x" size={14} /></button>}</label>
        {source !== 'file' && <select value={since} onChange={e => { setSince(e.target.value); }} onBlur={() => undefined} aria-label="Time range" className="lv-select">
          <option value="0">Any time</option><option value="15">Last 15 min</option><option value="60">Last hour</option><option value="360">Last 6 hours</option><option value="1440">Last 24 hours</option><option value="10080">Last 7 days</option></select>}
        <select value={lines} onChange={e => setLines(e.target.value)} aria-label="Number of lines" className="lv-select">{['100', '200', '500', '1000', '2000'].map(n => <option key={n} value={n}>{n} lines</option>)}</select>
        <button className="btn primary sm" disabled={busy || !target}>Apply</button>
        <div className="lv-levels" role="group" aria-label="Level filter">
          <button type="button" className={levelFilter === 'all' ? 'on' : ''} onClick={() => setLevelFilter('all')}>All</button>
          <button type="button" className={`err ${levelFilter === 'error' ? 'on' : ''}`} onClick={() => setLevelFilter(levelFilter === 'error' ? 'all' : 'error')}>Errors <b>{counts.error}</b></button>
          <button type="button" className={`wrn ${levelFilter === 'warn' ? 'on' : ''}`} onClick={() => setLevelFilter(levelFilter === 'warn' ? 'all' : 'warn')}>Warnings <b>{counts.warn}</b></button>
        </div>
      </form>
      {shell.notes.length > 0 && <div className="lv-note">{shell.notes.map((n, i) => <p key={i}><Icon name="alert" size={14} />{n}</p>)}</div>}
      {error && <div className="lv-error" role="alert"><Icon name="alert" size={15} />{error}<button className="btn sm" onClick={() => void fetchLogs()}>Retry</button></div>}

      <div className="lv-body">
        <div className="lv-cols"><span>#</span><span>Time</span><span>Level</span><span>Message</span></div>
        {output === null || (busy && output === null) ? (
          <div className="lv-skel">{Array.from({ length: 12 }, (_, i) => <i key={i} style={{ width: `${30 + ((i * 53) % 65)}%` }} />)}</div>
        ) : shown.length === 0 ? (
          <div className="lv-empty"><Icon name="logs" size={26} /><h3>{rows.length ? 'No lines at this level' : applied ? 'No lines match your search' : 'No log output'}</h3>
            <p>{rows.length ? 'Choose “All” to see every line.' : applied ? <>Nothing contains “{applied}” in the {lines} most recent lines. Try a different term or more lines.</> : 'This source has not written anything in the selected time range.'}</p></div>
        ) : (
          <div className={`lv-scroll ${wrap ? 'wrap' : ''}`} ref={scroller} onScroll={onScroll}>
            {shown.map(r => (
              <div key={r.n} className={`lv-row ${r.level}`}>
                <span className="n">{r.n}</span><span className="t" title={r.tsTitle}>{r.ts}</span>
                <span className="l">{r.level && <em className={r.level}>{LEVEL_LABEL[r.level]}</em>}</span>
                <span className="m"><Highlight text={r.msg} term={applied} /></span>
              </div>))}
          </div>)}
        {!stuck && shown.length > 0 && <button className="lv-jump" onClick={() => { setStuck(true); const el = scroller.current; if (el) el.scrollTop = el.scrollHeight; }}>↓ Jump to latest</button>}
      </div>

      <div className="lv-foot">
        <span><b>{shown.length.toLocaleString()}</b>{shown.length !== rows.length ? ` of ${rows.length.toLocaleString()}` : ''} lines</span>
        {counts.error > 0 && <span className="bad">{counts.error} error{counts.error === 1 ? '' : 's'}</span>}{counts.warn > 0 && <span className="warn">{counts.warn} warning{counts.warn === 1 ? '' : 's'}</span>}
        {truncated && <span className="warn">newest 400 KB only</span>}
        {fetchedAt && <span className="muted">fetched {fetchedAt.toLocaleTimeString()} · {took.toFixed(1)}s</span>}
        <span className="grow" />
        <label className="check"><input type="checkbox" checked={wrap} onChange={e => setWrap(e.target.checked)} />Wrap lines</label>
        <button className="btn ghost sm" onClick={() => void navigator.clipboard?.writeText(shown.map(r => `${r.ts} ${r.msg}`.trim()).join('\n'))} disabled={!shown.length}>Copy</button>
        <button className="btn ghost sm" onClick={download} disabled={!output}>Download</button>
      </div>
    </div>
  );
}
