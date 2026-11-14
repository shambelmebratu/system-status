'use client';

import { Fragment, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from './ui';

/* ================================================================================================ time ranges */
export const RANGES: { id: string; label: string; seconds: number; long: string }[] = [
  { id: '15s', label: '15s', seconds: 15, long: 'Last 15 seconds' }, { id: '1m', label: '1m', seconds: 60, long: 'Last minute' },
  { id: '5m', label: '5m', seconds: 300, long: 'Last 5 minutes' }, { id: '15m', label: '15m', seconds: 900, long: 'Last 15 minutes' },
  { id: '30m', label: '30m', seconds: 1800, long: 'Last 30 minutes' }, { id: '1h', label: '1h', seconds: 3600, long: 'Last hour' },
  { id: '6h', label: '6h', seconds: 21600, long: 'Last 6 hours' }, { id: '12h', label: '12h', seconds: 43200, long: 'Last 12 hours' },
  { id: '1d', label: '1d', seconds: 86400, long: 'Last day' }, { id: '7d', label: '7d', seconds: 604800, long: 'Last 7 days' },
  { id: '1mo', label: '1mo', seconds: 2592000, long: 'Last 30 days' },
];

/* ================================================================================================ parsing */
export type Level = 'error' | 'warn' | 'info' | 'debug' | '';
export type LogRow = { n: number; t: number | null; ts: string; tsTitle: string; level: Level; msg: string; raw: string; fields: [string, string][]; json?: unknown };
export type Row = LogRow;

const TS_PREFIX = [
  /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+/,   // docker, kubernetes, journald short-iso, app logs
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

function epoch(raw: string): number | null {
  let iso = raw.replace(' ', 'T').replace(',', '.').replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  if (/^\d{4}\/\d{2}\/\d{2}/.test(raw)) iso = raw.replace(/\//g, '-').replace(' ', 'T');
  if (/^[A-Z][a-z]{2}\s/.test(raw)) {   // syslog has no year: this year, or last year for a date that would be in the future
    const m = /^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})/.exec(raw);
    if (!m || !MONTHS[m[1]]) return null;
    const now = new Date();
    let t = Date.parse(`${now.getFullYear()}-${MONTHS[m[1]]}-${m[2].padStart(2, '0')}T${m[3]}`);
    if (t > now.getTime() + 86400000) t = Date.parse(`${now.getFullYear() - 1}-${MONTHS[m[1]]}-${m[2].padStart(2, '0')}T${m[3]}`);
    return isNaN(t) ? null : t;
  }
  iso = iso.replace(/(\.\d{3})\d+/, '$1');   // Kubernetes logs nanoseconds; Date understands milliseconds
  const t = Date.parse(iso);
  return isNaN(t) ? null : t;
}
const stamp = (t: number) => { const d = new Date(t); return { ts: d.toLocaleTimeString([], { hour12: false }), title: d.toLocaleString() }; };
const levelOf = (v: unknown): Level => {
  const s = String(v ?? '').toLowerCase();
  return /err|fatal|crit|panic|emerg|alert/.test(s) ? 'error' : /warn/.test(s) ? 'warn' : /info|notice/.test(s) ? 'info' : /debug|trace/.test(s) ? 'debug' : '';
};
const short = (v: unknown) => { const s = typeof v === 'object' ? JSON.stringify(v) : String(v); return s.length > 60 ? `${s.slice(0, 57)}…` : s; };

export function parse(output: string): LogRow[] {
  return output.split('\n').filter(l => l.length).map((line, i) => {
    let t: number | null = null, msg = line, fields: [string, string][] = [], json: unknown, level: Level = '';
    for (const rx of TS_PREFIX) {
      const m = rx.exec(line);
      if (m) { t = epoch(m[1]); msg = line.slice(m[0].length); break; }
    }
    if (t == null) {
      const nx = NGINX_TS.exec(line);
      if (nx) t = epoch(`${nx[3]}-${MONTHS[nx[2]] ?? '01'}-${nx[1]}T${nx[4]}${nx[5].slice(0, 3)}:${nx[5].slice(3)}`);
    }
    // Structured (JSON) logs: show the message, keep the other fields as tags, take the level and time from the object.
    const trimmed = msg.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const obj = JSON.parse(trimmed) as Record<string, unknown>;
        const take = (...keys: string[]) => { for (const k of keys) if (obj[k] != null) { const v = obj[k]; delete obj[k]; return v; } return undefined; };
        const when = take('time', 'ts', 'timestamp', '@timestamp', 't');
        if (t == null && when != null) t = typeof when === 'number' ? (when < 1e12 ? when * 1000 : when) : epoch(String(when));
        const lv = take('level', 'severity', 'lvl', 'log.level');
        const text = take('message', 'msg', 'log', 'event');
        json = JSON.parse(trimmed);
        level = levelOf(lv);
        fields = Object.entries(obj).slice(0, 6).map(([k, v]) => [k, short(v)]);
        msg = text != null ? String(text) : trimmed;
      } catch { /* not JSON after all */ }
    }
    const { ts, title } = t != null ? stamp(t) : { ts: '', title: '' };
    if (!level) {
      // HTTP access logs: the status code decides (5xx error, 4xx warning). Everything else is judged by its wording.
      const status = NGINX_STATUS.exec(line);
      level = status && status[1][0] === '5' ? 'error' : status && status[1][0] === '4' ? 'warn' : '';
      if (!level) level = ERR.test(msg) ? 'error' : WARN.test(msg) ? 'warn' : DBG.test(msg) ? 'debug' : INF.test(msg) ? 'info' : '';
    }
    // The badge already says it, so drop a leading "INFO:" / "ERROR " token from the text.
    const lead = /^\[?(INFO|WARN(?:ING)?|ERROR|ERR|DEBUG|NOTICE|CRITICAL|FATAL)\]?[:\s]+/i.exec(msg);
    if (lead && level) msg = msg.slice(lead[0].length);
    return { n: i + 1, t, ts, tsTitle: title, level, msg, raw: line, fields, json };
  });
}

const escapeRx = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export function Highlight({ text, term }: { text: string; term: string }) {
  if (!term) return <>{text}</>;
  const parts = text.split(new RegExp(`(${escapeRx(term)})`, 'ig'));
  return <>{parts.map((p, i) => (i % 2 ? <mark key={i}>{p}</mark> : <Fragment key={i}>{p}</Fragment>))}</>;
}
export const LEVEL_LABEL: Record<string, string> = { error: 'ERR', warn: 'WARN', info: 'INFO', debug: 'DBG' };
const LEVELS: { id: Exclude<Level, ''>; label: string }[] = [{ id: 'error', label: 'Errors' }, { id: 'warn', label: 'Warnings' }, { id: 'info', label: 'Info' }, { id: 'debug', label: 'Debug' }];

/* ================================================================================================ histogram */
type Bucket = { from: number; to: number; error: number; warn: number; other: number };

function Histogram({ rows, zoom, onZoom }: { rows: LogRow[]; zoom: [number, number] | null; onZoom: (z: [number, number] | null) => void }) {
  const [hover, setHover] = useState<number | null>(null);
  const timed = rows.filter(r => r.t != null) as (LogRow & { t: number })[];
  const buckets = useMemo<Bucket[]>(() => {
    if (timed.length < 2) return [];
    const lo = Math.min(...timed.map(r => r.t)), hi = Math.max(...timed.map(r => r.t));
    if (hi <= lo) return [];
    const n = 60, width = (hi - lo) / n || 1;
    const out: Bucket[] = Array.from({ length: n }, (_, i) => ({ from: lo + i * width, to: lo + (i + 1) * width, error: 0, warn: 0, other: 0 }));
    for (const r of timed) { const b = out[Math.min(n - 1, Math.floor((r.t - lo) / width))]; if (r.level === 'error') b.error++; else if (r.level === 'warn') b.warn++; else b.other++; }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows]);
  if (buckets.length === 0 || timed.length < rows.length / 2) return null;
  const max = Math.max(1, ...buckets.map(b => b.error + b.warn + b.other));
  const h = hover != null ? buckets[hover] : null;
  const fmt = (t: number) => new Date(t).toLocaleTimeString([], { hour12: false });
  return (
    <div className="lg-hist" onMouseLeave={() => setHover(null)}>
      <div className="lg-hist-bars" role="img" aria-label="Log volume over time">
        {buckets.map((b, i) => {
          const total = b.error + b.warn + b.other;
          const selected = zoom && b.from >= zoom[0] - 1 && b.to <= zoom[1] + 1;
          return (
            <button key={i} type="button" className={`lg-bar-col ${selected ? 'sel' : ''}`} onMouseEnter={() => setHover(i)} onClick={() => onZoom(selected ? null : [b.from, b.to])} aria-label={`${total} lines at ${fmt(b.from)}`}>
              <span className="lg-stack" style={{ height: `${(total / max) * 100}%` }}>
                {b.other > 0 && <i className="o" style={{ flex: b.other }} />}{b.warn > 0 && <i className="w" style={{ flex: b.warn }} />}{b.error > 0 && <i className="e" style={{ flex: b.error }} />}
              </span>
            </button>);
        })}
      </div>
      <div className="lg-hist-axis"><span>{fmt(buckets[0].from)}</span>
        <span className="lg-hist-tip">{h ? `${fmt(h.from)} · ${h.error + h.warn + h.other} lines${h.error ? ` · ${h.error} errors` : ''}${h.warn ? ` · ${h.warn} warnings` : ''}` : zoom ? `Zoomed to ${fmt(zoom[0])} – ${fmt(zoom[1])}` : 'Click a bar to zoom in'}</span>
        <span>{fmt(buckets[buckets.length - 1].to)}</span></div>
    </div>
  );
}

/* ================================================================================================ searchable picker */
export type PickerOption = { value: string; label: string; dot?: string; hint?: string };

/** A dropdown with a search box: usable with hundreds of entries (a server can have a thousand log files). */
export function TargetPicker({ value, options, onChange, placeholder = 'Choose…', icon, disabled, width = 300 }: { value: string; options: PickerOption[]; onChange: (v: string) => void; placeholder?: string; icon?: string; disabled?: boolean; width?: number }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [cursor, setCursor] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  const matches = useMemo(() => { const n = q.trim().toLowerCase(); return (n ? options.filter(o => `${o.label} ${o.hint ?? ''}`.toLowerCase().includes(n)) : options).slice(0, 300); }, [options, q]);
  const current = options.find(o => o.value === value);
  const choose = (v: string) => { onChange(v); setOpen(false); setQ(''); };
  return (
    <div className="pick-box" ref={box} style={{ width }}>
      <button type="button" className="pick-btn" disabled={disabled} onClick={() => { setOpen(!open); setCursor(0); }} aria-haspopup="listbox" aria-expanded={open}>
        {icon && <Icon name={icon} size={15} />}{current?.dot !== undefined && <i className="lv-dot" data-state={current.dot} />}
        <span className="pick-label">{current?.label ?? (value || placeholder)}</span><span className="pick-caret">▾</span>
      </button>
      {open && (
        <div className="pick-pop" role="listbox">
          <input autoFocus value={q} onChange={e => { setQ(e.target.value); setCursor(0); }} placeholder={`Search ${options.length.toLocaleString()} item${options.length === 1 ? '' : 's'}…`} aria-label="Search"
            onKeyDown={e => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setCursor(c => Math.min(matches.length - 1, c + 1)); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setCursor(c => Math.max(0, c - 1)); }
              else if (e.key === 'Enter' && matches[cursor]) { e.preventDefault(); choose(matches[cursor].value); }
              else if (e.key === 'Escape') setOpen(false);
            }} />
          <div className="pick-list">
            {matches.length === 0 ? <div className="pick-none">Nothing matches “{q}”</div> : matches.map((o, i) => (
              <button type="button" key={o.value} role="option" aria-selected={o.value === value} className={`pick-opt ${i === cursor ? 'cur' : ''} ${o.value === value ? 'sel' : ''}`} onMouseEnter={() => setCursor(i)} onClick={() => choose(o.value)}>
                {o.dot !== undefined && <i className="lv-dot" data-state={o.dot} />}<span className="pick-label">{o.label}</span>{o.hint && <small>{o.hint}</small>}
              </button>))}
            {options.length > matches.length && !q && <div className="pick-none">Showing the first {matches.length} of {options.length.toLocaleString()}: type to search</div>}
          </div>
        </div>)}
    </div>
  );
}

/* ================================================================================================ the viewer */
export type LogFetch = (q: { sinceSeconds: number; lines: number; grep: string }, isCancelled: () => boolean) => Promise<{ text: string; truncated: boolean }>;
type Prefs = { range: string; lines: string; wrap: boolean; dense: boolean; newest: boolean };
const DEFAULT_PREFS: Prefs = { range: '1h', lines: '500', wrap: true, dense: false, newest: false };

export function LogViewer({ fetcher, fetchKey, canFetch, controls, storageKey, downloadName, emptyHint, banner }: {
  fetcher: LogFetch; fetchKey: string; canFetch: boolean; controls?: ReactNode; storageKey: string; downloadName: string; emptyHint?: ReactNode; banner?: ReactNode;
}) {
  const [prefs, setPrefs] = useState<Prefs>(DEFAULT_PREFS);
  useEffect(() => { try { const v = JSON.parse(localStorage.getItem(`smw_logview_${storageKey}`) || 'null'); if (v) setPrefs({ ...DEFAULT_PREFS, ...v }); } catch { /* storage unavailable */ } }, [storageKey]);
  const setPref = <K extends keyof Prefs>(k: K, v: Prefs[K]) => setPrefs(p => { const n = { ...p, [k]: v }; try { localStorage.setItem(`smw_logview_${storageKey}`, JSON.stringify(n)); } catch { /* ignore */ } return n; });
  const range = RANGES.find(r => r.id === prefs.range) ?? RANGES[5];

  const [text, setText] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);
  const [took, setTook] = useState(0);
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState('');
  const [exclude, setExclude] = useState('');
  const [levels, setLevels] = useState<Set<string>>(new Set());
  const [zoom, setZoom] = useState<[number, number] | null>(null);
  const [live, setLive] = useState(false);
  const [liveMs, setLiveMs] = useState(3000);
  const [open, setOpen] = useState<number | null>(null);
  const [stuck, setStuck] = useState(true);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const run = useRef(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const prevKeys = useRef<Set<string>>(new Set());
  const scroller = useRef<HTMLDivElement>(null);
  const searchBox = useRef<HTMLInputElement>(null);

  const doFetch = useCallback(async (quiet = false) => {
    if (!canFetch) return;
    const mine = ++run.current;
    const started = performance.now();
    if (!quiet) setBusy(true);
    setError('');
    try {
      const r = await fetcherRef.current({ sinceSeconds: range.seconds, lines: Number(prefs.lines), grep: applied }, () => run.current !== mine);
      if (run.current !== mine) return;
      setText(r.text); setTruncated(r.truncated); setFetchedAt(new Date()); setTook((performance.now() - started) / 1000);
    } catch (e) { if ((e as Error).message !== 'cancelled' && run.current === mine) setError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [canFetch, range.seconds, prefs.lines, applied]);

  // A different log, time range, line limit or search starts a fresh fetch.
  useEffect(() => { setText(null); setOpen(null); setZoom(null); prevKeys.current = new Set(); setFresh(new Set()); void doFetch(); return () => { run.current++; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchKey, range.seconds, prefs.lines, applied, canFetch]);
  useEffect(() => { setLive(false); setSearch(''); setApplied(''); setExclude(''); setLevels(new Set()); }, [fetchKey]);
  useEffect(() => { if (!live) return; const t = setInterval(() => { if (!document.hidden) void doFetch(true); }, liveMs); return () => clearInterval(t); }, [live, liveMs, doFetch]);
  useEffect(() => { const k = (e: KeyboardEvent) => { if (e.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') { e.preventDefault(); searchBox.current?.focus(); } }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, []);

  const rows = useMemo(() => (text ? parse(text) : []), [text]);
  // Lines that were not there on the previous refresh get a brief highlight while tailing.
  useEffect(() => {
    const keys = new Set(rows.map(r => `${r.t ?? ''}|${r.raw}`));
    if (live && prevKeys.current.size) setFresh(new Set([...keys].filter(k => !prevKeys.current.has(k))));
    else setFresh(new Set());
    prevKeys.current = keys;
  }, [rows, live]);

  const counts = useMemo(() => ({ error: rows.filter(r => r.level === 'error').length, warn: rows.filter(r => r.level === 'warn').length, info: rows.filter(r => r.level === 'info').length, debug: rows.filter(r => r.level === 'debug').length }), [rows]);
  const needle = exclude.trim().toLowerCase();
  const filtered = useMemo(() => rows.filter(r => (levels.size === 0 || levels.has(r.level || 'info'))
    && (!needle || !r.raw.toLowerCase().includes(needle))
    && (!zoom || (r.t != null && r.t >= zoom[0] - 1 && r.t <= zoom[1] + 1))), [rows, levels, needle, zoom]);
  const shown = useMemo(() => (prefs.newest ? [...filtered].reverse() : filtered), [filtered, prefs.newest]);

  useEffect(() => { const el = scroller.current; if (el && stuck) el.scrollTop = prefs.newest ? 0 : el.scrollHeight; }, [shown, stuck, prefs.newest]);
  const onScroll = () => { const el = scroller.current; if (el) setStuck(prefs.newest ? el.scrollTop < 40 : el.scrollHeight - el.scrollTop - el.clientHeight < 40); };

  const toggleLevel = (id: string) => setLevels(s => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const copy = (value: string) => void navigator.clipboard?.writeText(value);
  const download = () => {
    const url = URL.createObjectURL(new Blob([shown.map(r => r.raw).join('\n')], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = `${downloadName.replace(/[^A-Za-z0-9_.-]+/g, '_') || 'logs'}.log`; a.click(); URL.revokeObjectURL(url);
  };
  const nextRange = RANGES[Math.min(RANGES.length - 1, RANGES.findIndex(r => r.id === range.id) + 3)];
  const filtersOn = levels.size > 0 || !!needle || !!zoom;

  return (
    <div className="lg">
      {controls && <div className="lg-controls">{controls}</div>}
      {banner}
      <div className="lg-toolbar">
        <div className="lg-range" role="group" aria-label="Time range">
          <span className="lg-range-label"><Icon name="clock" size={14} /></span>
          {RANGES.map(r => <button key={r.id} type="button" className={r.id === range.id ? 'on' : ''} title={r.long} aria-pressed={r.id === range.id} onClick={() => setPref('range', r.id)}>{r.label}</button>)}
        </div>
        <span className="grow" />
        <button type="button" className={`lg-live ${live ? 'on' : ''}`} onClick={() => setLive(!live)} aria-pressed={live} title="Keep fetching new lines"><i />{live ? 'Live' : 'Live tail'}</button>
        {live && <select className="lg-mini" value={liveMs} onChange={e => setLiveMs(Number(e.target.value))} aria-label="Refresh every"><option value={2000}>2 s</option><option value={3000}>3 s</option><option value={5000}>5 s</option><option value={10000}>10 s</option></select>}
        <button type="button" className="btn sm" onClick={() => void doFetch()} disabled={busy || !canFetch}><Icon name="refresh" size={14} />{busy ? 'Loading…' : 'Refresh'}</button>
      </div>

      <form className="lg-search" onSubmit={e => { e.preventDefault(); setApplied(search); }}>
        <label className="lg-field grow"><Icon name="logs" size={15} /><input ref={searchBox} value={search} onChange={e => setSearch(e.target.value)} placeholder="Search the logs…   ( / )" maxLength={200} aria-label="Search" />
          {(search || applied) && <button type="button" aria-label="Clear search" onClick={() => { setSearch(''); setApplied(''); }}><Icon name="x" size={14} /></button>}</label>
        <label className="lg-field narrow"><span className="lg-minus">−</span><input value={exclude} onChange={e => setExclude(e.target.value)} placeholder="Exclude lines containing…" maxLength={100} aria-label="Exclude" />
          {exclude && <button type="button" aria-label="Clear exclude" onClick={() => setExclude('')}><Icon name="x" size={14} /></button>}</label>
        <button className="btn primary sm" disabled={busy || !canFetch}>Search</button>
      </form>

      <div className="lg-levels2">
        {LEVELS.map(l => <button key={l.id} type="button" className={`lg-lvl ${l.id} ${levels.has(l.id) ? 'on' : ''}`} aria-pressed={levels.has(l.id)} onClick={() => toggleLevel(l.id)}><i />{l.label}<b>{counts[l.id].toLocaleString()}</b></button>)}
        {filtersOn && <button type="button" className="lg-clear" onClick={() => { setLevels(new Set()); setExclude(''); setZoom(null); }}>Clear filters</button>}
        <span className="grow" />
        <label className="lg-opt"><input type="checkbox" checked={prefs.wrap} onChange={e => setPref('wrap', e.target.checked)} />Wrap</label>
        <label className="lg-opt"><input type="checkbox" checked={prefs.dense} onChange={e => setPref('dense', e.target.checked)} />Compact</label>
        <label className="lg-opt"><input type="checkbox" checked={prefs.newest} onChange={e => setPref('newest', e.target.checked)} />Newest first</label>
        <select className="lg-mini" value={prefs.lines} onChange={e => setPref('lines', e.target.value)} aria-label="Lines to load">{['100', '200', '500', '1000', '2000'].map(n => <option key={n} value={n}>{n} lines</option>)}</select>
      </div>

      <Histogram rows={rows} zoom={zoom} onZoom={setZoom} />
      {error && <div className="lg-error" role="alert"><Icon name="alert" size={15} /><span>{error}</span><button className="btn sm" onClick={() => void doFetch()}>Retry</button></div>}

      <div className={`lg-body ${prefs.dense ? 'dense' : ''} ${prefs.wrap ? 'wrap' : ''}`}>
        {text === null ? (
          <div className="lg-skel">{Array.from({ length: 12 }, (_, i) => <i key={i} style={{ width: `${30 + ((i * 53) % 62)}%` }} />)}</div>
        ) : shown.length === 0 ? (
          <div className="lg-empty"><Icon name="logs" size={28} /><h3>{rows.length ? 'No lines match your filters' : applied ? `Nothing contains “${applied}”` : `No log lines in the ${range.long.toLowerCase()}`}</h3>
            <p>{rows.length ? 'Clear the level, exclude or zoom filters.' : applied ? 'Try a different search term or a wider time range.' : <>This log has been quiet. {range.id !== '1mo' && <button type="button" className="lg-link" onClick={() => setPref('range', nextRange.id)}>Look back further ({nextRange.long.toLowerCase()})</button>}</>}</p>
            {emptyHint}</div>
        ) : (
          <div className="lg-scroll" ref={scroller} onScroll={onScroll}>
            {shown.map(r => {
              const isOpen = open === r.n;
              const isNew = fresh.has(`${r.t ?? ''}|${r.raw}`);
              return (
                <div key={r.n} className={`lg-item ${r.level} ${isOpen ? 'open' : ''} ${isNew ? 'new' : ''}`}>
                  <div className="lg-row" onClick={() => setOpen(isOpen ? null : r.n)} role="button" tabIndex={0} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setOpen(isOpen ? null : r.n))} aria-expanded={isOpen}>
                    <span className="lg-t" title={r.tsTitle}>{r.ts}</span>
                    <span className="lg-l">{r.level ? <em className={r.level}>{LEVEL_LABEL[r.level]}</em> : null}</span>
                    <span className="lg-m"><Highlight text={r.msg} term={applied} />{r.fields.map(([k, v]) => <span key={k} className="lg-tag"><i>{k}</i>{v}</span>)}</span>
                  </div>
                  {isOpen && (
                    <div className="lg-detail">
                      <div className="lg-detail-bar"><span className="muted sm">{r.tsTitle || 'no timestamp'}{r.level ? ` · ${r.level}` : ''}</span><span className="grow" />
                        <button type="button" className="btn sm ghost" onClick={() => copy(r.raw)}>Copy line</button>
                        {r.json !== undefined && <button type="button" className="btn sm ghost" onClick={() => copy(JSON.stringify(r.json, null, 2))}>Copy JSON</button>}
                        {r.t != null && <button type="button" className="btn sm ghost" onClick={() => setZoom([r.t! - 30000, r.t! + 30000])} title="Show only the surrounding minute">± 30 s</button>}</div>
                      <pre>{r.json !== undefined ? JSON.stringify(r.json, null, 2) : r.raw}</pre>
                    </div>)}
                </div>);
            })}
          </div>)}
        {!stuck && shown.length > 0 && <button className="lg-jump" onClick={() => { setStuck(true); const el = scroller.current; if (el) el.scrollTop = prefs.newest ? 0 : el.scrollHeight; }}>{prefs.newest ? '↑ Jump to newest' : '↓ Jump to newest'}{fresh.size ? ` · ${fresh.size} new` : ''}</button>}
      </div>

      <div className="lg-foot">
        <span><b>{shown.length.toLocaleString()}</b>{shown.length !== rows.length ? ` of ${rows.length.toLocaleString()}` : ''} lines</span>
        {truncated && <span className="warn">showing the newest part only</span>}
        {fetchedAt && <span className="muted">{live ? 'live · ' : ''}updated {fetchedAt.toLocaleTimeString([], { hour12: false })} · {took.toFixed(1)}s</span>}
        <span className="grow" />
        <button type="button" className="btn ghost sm" onClick={() => copy(shown.map(r => r.raw).join('\n'))} disabled={!shown.length}>Copy</button>
        <button type="button" className="btn ghost sm" onClick={download} disabled={!shown.length}>Download</button>
      </div>
    </div>
  );
}
