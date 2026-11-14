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
export function tryRegex(source: string): RegExp | null { try { return source ? new RegExp(source, 'i') : null; } catch { return null; } }
export function Highlight({ text, term, regex }: { text: string; term: string; regex?: boolean }) {
  if (!term) return <>{text}</>;
  let rx: RegExp;
  try { rx = new RegExp(`(${regex ? term : escapeRx(term)})`, 'ig'); } catch { return <>{text}</>; }
  if (rx.test('')) return <>{text}</>;   // a pattern that matches nothing at all would split every character
  const parts = text.split(rx);
  return <>{parts.map((p, i) => (i % 2 ? <mark key={i}>{p}</mark> : <Fragment key={i}>{p}</Fragment>))}</>;
}

/* ---- clickable pieces of a line: quoted strings, IP addresses, paths, UUIDs ---- */
export type Segment = { text: string; kind?: 'ip' | 'path' | 'str' | 'id'; value?: string };
const TOKEN_RX = /("[^"\n]{3,}")|(\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\b)|(\/[\w.\-@%+~]{2,}(?:\/[\w.\-@%+~]+)*)|(\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)/gi;
export function segments(text: string): Segment[] {
  const out: Segment[] = [];
  let last = 0;
  TOKEN_RX.lastIndex = 0;
  for (let m = TOKEN_RX.exec(text); m; m = TOKEN_RX.exec(text)) {
    if (m[3] && m.index > 0 && /[\w:.]/.test(text[m.index - 1])) continue;   // "host:/x" or "a.b/c" is not a path of its own
    if (m.index > last) out.push({ text: text.slice(last, m.index) });
    const kind = m[1] ? 'str' : m[2] ? 'ip' : m[3] ? 'path' : 'id';
    out.push({ text: m[0], kind, value: kind === 'str' ? m[0].slice(1, -1) : m[0] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

/** Lines that say the same thing with different numbers (ids, durations, addresses) share a signature, so they can be folded together. */
export const signature = (r: LogRow) => `${r.level}|${r.msg.replace(/\b[0-9a-f]{8,}\b/gi, '?').replace(/\d+/g, '#').slice(0, 240)}`;

/* ---- what common errors usually mean (pattern based, not a diagnosis) ---- */
export const HINTS: { test: RegExp; title: string; text: string; fix?: string }[] = [
  { test: /rewrite or internal redirection cycle/i, title: 'nginx is redirecting to itself', text: 'try_files / rewrite keeps sending the request back to the same location, usually because the fallback file (often /index.html) does not exist under the root or is not readable by the nginx worker.', fix: 'location / {\n  root /var/www/app/dist;          # must contain index.html\n  try_files $uri $uri/ /index.html;\n}' },
  { test: /upstream prematurely closed/i, title: 'The backend hung up mid-response', text: 'The upstream application closed the connection before it finished answering: it crashed, was restarted, or hit its own timeout. Check the application logs at the same minute.', fix: 'proxy_read_timeout 60s;     # and look for a crash or OOM kill of the upstream around this time' },
  { test: /upstream timed out|ETIMEDOUT|timed out|context deadline exceeded|i\/o timeout/i, title: 'A call took too long', text: 'Something did not answer in time: a slow or overloaded upstream/database, a firewall dropping packets, or a timeout set too low.' },
  { test: /connection refused|ECONNREFUSED/i, title: 'Nothing is listening there', text: 'The target address answered, but no process accepts connections on that port: the service is down, still starting, or listening on a different address/port.' },
  { test: /connection reset by peer|ECONNRESET|broken pipe|EPIPE/i, title: 'The other side dropped the connection', text: 'The peer closed the connection abruptly: often a crash/restart, a proxy idle timeout, or a client that gave up.' },
  { test: /No such file or directory|ENOENT/i, title: 'A file or directory is missing', text: 'The path in the message does not exist on that machine. Check the spelling, a missing mount/volume, or a deploy that did not copy the file.' },
  { test: /Permission denied|EACCES|Forbidden|not permitted/i, title: 'Permission problem', text: 'The process is not allowed to read, write or run that. Check ownership and mode of the path and the user the service runs as (and SELinux/AppArmor).' },
  { test: /OOMKilled|out of memory|oom-kill|Cannot allocate memory/i, title: 'Out of memory', text: 'The process was killed (or could not start) because memory ran out. Raise the memory limit or find the leak; compare with the Memory chart of this server.' },
  { test: /CrashLoopBackOff/i, title: 'Container keeps crashing', text: 'Kubernetes restarts the container, it exits again, and the wait between restarts grows. Read the previous container\'s logs ("Previous (crashed) container") for the real error.' },
  { test: /ImagePullBackOff|ErrImagePull/i, title: 'Image cannot be pulled', text: 'The image name/tag is wrong, does not exist, or the registry needs credentials (imagePullSecrets).' },
  { test: /no space left on device|ENOSPC/i, title: 'Disk is full', text: 'A filesystem (or inode table) is full. Check the Disk chart; clear old logs/backups or grow the volume.' },
  { test: /too many open files|EMFILE|ENFILE/i, title: 'File descriptor limit reached', text: 'The process opened more files/sockets than allowed. Raise the limit (ulimit -n / LimitNOFILE) or fix a descriptor leak.' },
  { test: /address already in use|EADDRINUSE/i, title: 'Port already taken', text: 'Another process (often a previous instance) is already bound to that port.' },
  { test: /limiting requests|limit_req|rate.?limit|429/i, title: 'Rate limit hit', text: 'Requests were throttled by a rate limit. Fine if it targets abusive clients; otherwise raise the limit or find the client that is hammering the endpoint.' },
  { test: /deadlock|lock wait timeout/i, title: 'Database lock contention', text: 'Two transactions are waiting on each other, or one waited too long for a lock. Look for long-running transactions around this time.' },
  { test: /certificate|x509|SSL|TLS handshake/i, title: 'TLS / certificate problem', text: 'The certificate is expired, not trusted, or for another name; or the two sides cannot agree on a protocol.' },
];
export const hintFor = (raw: string) => HINTS.find(h => h.test.test(raw));

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
  const totals = buckets.map(b => b.error + b.warn + b.other);
  const mean = totals.reduce((x, y) => x + y, 0) / totals.length;
  const sd = Math.sqrt(totals.reduce((x, y) => x + (y - mean) ** 2, 0) / totals.length);
  const peakIdx = totals.indexOf(Math.max(...totals));
  const spike = totals[peakIdx] >= Math.max(6, mean + 2 * sd) && totals[peakIdx] >= mean * 2 ? buckets[peakIdx] : null;
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
      {spike && <button type="button" className="lg-spike" onClick={() => onZoom([spike.from, spike.to])} title="Zoom in on the busiest moment"><Icon name="zap" size={13} />Spike at {fmt(spike.from)}: {spike.error + spike.warn + spike.other} lines{spike.error ? `, ${spike.error} errors` : ''} ({(totals[peakIdx] / Math.max(1, mean)).toFixed(1)}× the usual)</button>}
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

/* ================================================================================================ palette (⌘K) */
export type PaletteGroup = { label: string; icon: string; options: PickerOption[]; onPick: (value: string) => void };
/** One search box over every log a server can show (containers, journal units, files): switch with the keyboard. */
export function LogPalette({ open, onClose, groups, title }: { open: boolean; onClose: () => void; groups: PaletteGroup[]; title: string }) {
  const [q, setQ] = useState('');
  const [cursor, setCursor] = useState(0);
  useEffect(() => { if (open) { setQ(''); setCursor(0); } }, [open]);
  const flat = useMemo(() => {
    const n = q.trim().toLowerCase();
    return groups.flatMap(g => g.options.filter(o => !n || `${o.label} ${o.hint ?? ''} ${g.label}`.toLowerCase().includes(n)).slice(0, 60).map(o => ({ g, o })));
  }, [groups, q]);
  if (!open) return null;
  const choose = (i: number) => { const x = flat[i]; if (x) { x.g.onPick(x.o.value); onClose(); } };
  let lastGroup = '';
  return (
    <div className="overlay" style={{ placeItems: 'start center', paddingTop: '12vh' }} onMouseDown={e => e.target === e.currentTarget && onClose()}>
      <div className="modal palette" role="dialog" aria-modal="true" aria-label="Switch log" style={{ maxWidth: 600, padding: 0, gap: 0 }}>
        <div className="palette-head"><Icon name="logs" size={16} /><input autoFocus value={q} onChange={e => { setQ(e.target.value); setCursor(0); }} placeholder={title}
          onKeyDown={e => { if (e.key === 'ArrowDown') { e.preventDefault(); setCursor(c => Math.min(flat.length - 1, c + 1)); } else if (e.key === 'ArrowUp') { e.preventDefault(); setCursor(c => Math.max(0, c - 1)); } else if (e.key === 'Enter') { e.preventDefault(); choose(cursor); } else if (e.key === 'Escape') onClose(); }} /><kbd>esc</kbd></div>
        <div className="palette-list">
          {flat.length === 0 ? <div className="pick-none">Nothing matches “{q}”</div> : flat.map((x, i) => {
            const head = x.g.label !== lastGroup ? (lastGroup = x.g.label, <div key={`h-${x.g.label}`} className="palette-group"><Icon name={x.g.icon} size={12} />{x.g.label}</div>) : null;
            return <Fragment key={`${x.g.label}-${x.o.value}`}>{head}<button type="button" className={`pick-opt ${i === cursor ? 'cur' : ''}`} onMouseEnter={() => setCursor(i)} onClick={() => choose(i)}>
              {x.o.dot !== undefined && <i className="lv-dot" data-state={x.o.dot} />}<span className="pick-label">{x.o.label}</span>{x.o.hint && <small>{x.o.hint}</small>}</button></Fragment>;
          })}
        </div>
        <div className="palette-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div>
      </div>
    </div>
  );
}

/* ================================================================================================ inspector */
function LogInspector({ row, index, total, onClose, onNav, onToken, tokens, onZoom }: { row: LogRow; index: number; total: number; onClose: () => void; onNav: (d: number) => void; onToken: (t: string) => void; tokens: Set<string>; onZoom: (z: [number, number]) => void }) {
  const [copied, setCopied] = useState('');
  const copy = (what: string, value: string) => { void navigator.clipboard?.writeText(value); setCopied(what); setTimeout(() => setCopied(''), 1500); };
  const hint = hintFor(row.raw);
  const found = useMemo(() => {
    const seen = new Set<string>(); const out: { kind: string; value: string }[] = [];
    for (const sg of segments(row.msg)) if (sg.kind && sg.value && !seen.has(sg.value)) { seen.add(sg.value); out.push({ kind: sg.kind, value: sg.value }); }
    return out.slice(0, 12);
  }, [row.msg]);
  const KIND: Record<string, string> = { ip: 'Address', path: 'Path', str: 'Quoted', id: 'ID' };
  return (
    <div className="drawer-overlay lg-insp-overlay" onMouseDown={e => e.target === e.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Log line">
        <div className="drawer-head">
          <div style={{ minWidth: 0, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            {row.level && <em className={`lg-badge ${row.level}`}>{LEVEL_LABEL[row.level]}</em>}<b className="mono">Line #{row.n}</b><span className="muted sm mono">{row.tsTitle || 'no timestamp'}</span>
          </div>
          <span className="grow" />
          <button className="btn ghost sm" onClick={() => onNav(-1)} disabled={index <= 0} aria-label="Previous line" title="Previous (↑)">↑</button>
          <button className="btn ghost sm" onClick={() => onNav(1)} disabled={index >= total - 1} aria-label="Next line" title="Next (↓)">↓</button>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
        </div>
        <div className="drawer-actions">
          <button className="btn sm" onClick={() => copy('raw', row.raw)}>{copied === 'raw' ? 'Copied' : 'Copy line'}</button>
          {row.json !== undefined && <button className="btn sm" onClick={() => copy('json', JSON.stringify(row.json, null, 2))}>{copied === 'json' ? 'Copied' : 'Copy JSON'}</button>}
          {row.t != null && <button className="btn sm" onClick={() => { onZoom([row.t! - 30000, row.t! + 30000]); onClose(); }} title="Show only the surrounding minute">Context ± 30 s</button>}
        </div>
        <div className="drawer-body">
          {hint && (
            <div className="lg-hint"><div className="lg-hint-head"><Icon name="zap" size={14} /><b>{hint.title}</b><span className="muted sm">pattern-based hint</span></div>
              <p>{hint.text}</p>{hint.fix && <pre>{hint.fix}</pre>}</div>)}
          {found.length > 0 && <>
            <h3 className="drawer-h">Found in this line <span className="muted" style={{ textTransform: 'none', letterSpacing: 0 }}>· click to filter</span></h3>
            <div className="lg-found">{found.map(f => <button key={f.value} className={`lg-tok ${f.kind} ${tokens.has(f.value) ? 'on' : ''}`} onClick={() => onToken(f.value)} title={`Filter lines containing ${f.value}`}><i>{KIND[f.kind]}</i>{f.value}</button>)}</div></>}
          {row.fields.length > 0 && <>
            <h3 className="drawer-h">Fields</h3>
            <div className="facts">{Object.entries((row.json ?? {}) as Record<string, unknown>).slice(0, 24).map(([k, v]) => <div key={k}><small>{k}</small><b title={typeof v === 'object' ? JSON.stringify(v) : String(v)}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</b></div>)}</div></>}
          <h3 className="drawer-h">{row.json !== undefined ? 'JSON' : 'Raw line'}</h3>
          <pre className="lg-raw">{row.json !== undefined ? JSON.stringify(row.json, null, 2) : row.raw}</pre>
        </div>
      </aside>
    </div>
  );
}

/* ================================================================================================ the viewer */
export type LogFetch = (q: { sinceSeconds: number; lines: number; grep: string }, isCancelled: () => boolean) => Promise<{ text: string; truncated: boolean }>;
type Prefs = { range: string; lines: string; wrap: boolean; dense: boolean; newest: boolean; group: boolean };
const DEFAULT_PREFS: Prefs = { range: '1h', lines: '500', wrap: true, dense: false, newest: false, group: true };
type Entry = { key: string; row: LogRow; items: LogRow[] };

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
  const [useRegex, setUseRegex] = useState(false);
  const [exclude, setExclude] = useState('');
  const [levels, setLevels] = useState<Set<string>>(new Set());
  const [tokens, setTokens] = useState<Set<string>>(new Set());
  const [zoom, setZoom] = useState<[number, number] | null>(null);
  const [live, setLive] = useState(false);
  const [liveMs, setLiveMs] = useState(3000);
  const [selected, setSelected] = useState<number | null>(null);
  const [folded, setFolded] = useState<Set<string>>(new Set());
  const [stuck, setStuck] = useState(true);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const run = useRef(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const prevKeys = useRef<Set<string>>(new Set());
  const scroller = useRef<HTMLDivElement>(null);
  const searchBox = useRef<HTMLInputElement>(null);
  const serverGrep = useRegex ? '' : applied;   // a regular expression is applied here on the fetched lines; plain text is searched by the agent too

  const doFetch = useCallback(async (quiet = false) => {
    if (!canFetch) return;
    const mine = ++run.current;
    const started = performance.now();
    if (!quiet) setBusy(true);
    setError('');
    try {
      const r = await fetcherRef.current({ sinceSeconds: range.seconds, lines: Number(prefs.lines), grep: serverGrep }, () => run.current !== mine);
      if (run.current !== mine) return;
      setText(r.text); setTruncated(r.truncated); setFetchedAt(new Date()); setTook((performance.now() - started) / 1000);
    } catch (e) { if ((e as Error).message !== 'cancelled' && run.current === mine) setError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [canFetch, range.seconds, prefs.lines, serverGrep]);

  // A different log, time range, line limit or search starts a fresh fetch.
  useEffect(() => { setText(null); setSelected(null); setZoom(null); prevKeys.current = new Set(); setFresh(new Set()); void doFetch(); return () => { run.current++; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchKey, range.seconds, prefs.lines, serverGrep, canFetch]);
  useEffect(() => { setLive(false); setSearch(''); setApplied(''); setExclude(''); setLevels(new Set()); setTokens(new Set()); setFolded(new Set()); }, [fetchKey]);
  useEffect(() => { if (!live) return; const t = setInterval(() => { if (!document.hidden) void doFetch(true); }, liveMs); return () => clearInterval(t); }, [live, liveMs, doFetch]);
  useEffect(() => { const k = (e: KeyboardEvent) => { if (e.key === '/' && !(e.metaKey || e.ctrlKey) && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA' && document.activeElement?.tagName !== 'SELECT') { e.preventDefault(); searchBox.current?.focus(); } }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, []);

  const rows = useMemo(() => (text ? parse(text) : []), [text]);
  useEffect(() => {
    const keys = new Set(rows.map(r => `${r.t ?? ''}|${r.raw}`));
    if (live && prevKeys.current.size) setFresh(new Set([...keys].filter(k => !prevKeys.current.has(k))));
    else setFresh(new Set());
    prevKeys.current = keys;
  }, [rows, live]);

  const counts = useMemo(() => ({ error: rows.filter(r => r.level === 'error').length, warn: rows.filter(r => r.level === 'warn').length, info: rows.filter(r => r.level === 'info').length, debug: rows.filter(r => r.level === 'debug').length }), [rows]);
  const needle = exclude.trim().toLowerCase();
  const rx = useMemo(() => (useRegex ? tryRegex(applied) : null), [useRegex, applied]);
  const badRegex = useRegex && !!applied && !rx;
  const filtered = useMemo(() => rows.filter(r => (levels.size === 0 || levels.has(r.level || 'info'))
    && (!needle || !r.raw.toLowerCase().includes(needle))
    && (!zoom || (r.t != null && r.t >= zoom[0] - 1 && r.t <= zoom[1] + 1))
    && [...tokens].every(t => r.raw.includes(t))
    && (!rx || rx.test(r.raw))), [rows, levels, needle, zoom, tokens, rx]);
  // Runs of lines that say the same thing are folded into one expandable row ("13× similar").
  const entries = useMemo<Entry[]>(() => {
    const list: Entry[] = [];
    if (!prefs.group) filtered.forEach(r => list.push({ key: `r${r.n}`, row: r, items: [r] }));
    else for (const r of filtered) { const last = list[list.length - 1]; if (last && signature(last.row) === signature(r)) last.items.push(r); else list.push({ key: `g${r.n}`, row: r, items: [r] }); }
    return prefs.newest ? list.reverse() : list;
  }, [filtered, prefs.group, prefs.newest]);
  const saved = filtered.length - entries.length;
  const flat = useMemo(() => entries.flatMap(e => (e.items.length > 1 && !folded.has(e.key) ? [e.row] : e.items)), [entries, folded]);   // what Up/Down in the inspector walks through
  const selIndex = flat.findIndex(r => r.n === selected);
  const selRow = selIndex >= 0 ? flat[selIndex] : rows.find(r => r.n === selected) ?? null;

  useEffect(() => { const el = scroller.current; if (el && stuck) el.scrollTop = prefs.newest ? 0 : el.scrollHeight; }, [entries, stuck, prefs.newest]);
  const onScroll = () => { const el = scroller.current; if (el) setStuck(prefs.newest ? el.scrollTop < 40 : el.scrollHeight - el.scrollTop - el.clientHeight < 40); };
  useEffect(() => {
    if (selected == null) return;
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelected(null); else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const i = flat.findIndex(r => r.n === selected) + (e.key === 'ArrowDown' ? 1 : -1); if (flat[i]) setSelected(flat[i].n); } };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [selected, flat]);

  const toggleLevel = (id: string) => setLevels(s => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const toggleToken = (t: string) => setTokens(s => { const n = new Set(s); if (n.has(t)) n.delete(t); else n.add(t); return n; });
  const toggleFold = (key: string) => setFolded(s => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; });
  const copy = (value: string) => void navigator.clipboard?.writeText(value);
  const download = () => {
    const url = URL.createObjectURL(new Blob([filtered.map(r => r.raw).join('\n')], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = `${downloadName.replace(/[^A-Za-z0-9_.-]+/g, '_') || 'logs'}.log`; a.click(); URL.revokeObjectURL(url);
  };
  const nextRange = RANGES[Math.min(RANGES.length - 1, RANGES.findIndex(r => r.id === range.id) + 3)];
  const filtersOn = levels.size > 0 || !!needle || !!zoom || tokens.size > 0;
  const clearAll = () => { setLevels(new Set()); setExclude(''); setZoom(null); setTokens(new Set()); };
  const fmtT = (t: number) => new Date(t).toLocaleTimeString([], { hour12: false });

  /** A message with its addresses, paths and quoted strings turned into click-to-filter chips. */
  const message = (r: LogRow) => (
    <>{segments(r.msg).map((sg, i) => sg.kind
      ? <button key={i} type="button" className={`lg-tok ${sg.kind} ${tokens.has(sg.value!) ? 'on' : ''}`} onClick={e => { e.stopPropagation(); toggleToken(sg.value!); }} title="Click to show only lines containing this">{sg.text}</button>
      : <Highlight key={i} text={sg.text} term={applied} regex={useRegex} />)}
      {r.fields.map(([k, v]) => <span key={k} className="lg-tag"><i>{k}</i>{v}</span>)}</>
  );

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
        <label className={`lg-field grow ${badRegex ? 'bad' : ''}`}><Icon name="logs" size={15} /><input ref={searchBox} value={search} onChange={e => setSearch(e.target.value)} placeholder={useRegex ? 'Regular expression…   ( / )' : 'Search the logs…   ( / )'} maxLength={200} aria-label="Search" />
          {(search || applied) && <button type="button" aria-label="Clear search" onClick={() => { setSearch(''); setApplied(''); }}><Icon name="x" size={14} /></button>}
          <button type="button" className={`lg-rx ${useRegex ? 'on' : ''}`} onClick={() => setUseRegex(!useRegex)} aria-pressed={useRegex} title="Treat the search as a regular expression">.*</button></label>
        <label className="lg-field narrow"><span className="lg-minus">−</span><input value={exclude} onChange={e => setExclude(e.target.value)} placeholder="Exclude lines containing…" maxLength={100} aria-label="Exclude" />
          {exclude && <button type="button" aria-label="Clear exclude" onClick={() => setExclude('')}><Icon name="x" size={14} /></button>}</label>
        <button className="btn primary sm" disabled={busy || !canFetch}>Search</button>
      </form>
      {badRegex && <div className="lg-rxerr">That is not a valid regular expression, so nothing is filtered yet.</div>}

      <div className="lg-levels2">
        {LEVELS.map(l => <button key={l.id} type="button" className={`lg-lvl ${l.id} ${levels.has(l.id) ? 'on' : ''}`} aria-pressed={levels.has(l.id)} onClick={() => toggleLevel(l.id)}><i />{l.label}<b>{counts[l.id].toLocaleString()}</b></button>)}
        <button type="button" className={`lg-lvl grp ${prefs.group ? 'on' : ''}`} aria-pressed={prefs.group} onClick={() => setPref('group', !prefs.group)} title="Fold runs of lines that say the same thing into one row"><Icon name="overview" size={13} />Group similar{prefs.group && saved > 0 && <b>{saved.toLocaleString()} folded</b>}</button>
        <span className="grow" />
        <label className="lg-opt"><input type="checkbox" checked={prefs.wrap} onChange={e => setPref('wrap', e.target.checked)} />Wrap</label>
        <label className="lg-opt"><input type="checkbox" checked={prefs.dense} onChange={e => setPref('dense', e.target.checked)} />Compact</label>
        <label className="lg-opt"><input type="checkbox" checked={prefs.newest} onChange={e => setPref('newest', e.target.checked)} />Newest first</label>
        <select className="lg-mini" value={prefs.lines} onChange={e => setPref('lines', e.target.value)} aria-label="Lines to load">{['100', '200', '500', '1000', '2000'].map(n => <option key={n} value={n}>{n} lines</option>)}</select>
      </div>

      {filtersOn && (
        <div className="lg-active">
          <span className="muted sm">Filters:</span>
          {zoom && <button type="button" className="lg-chip" onClick={() => setZoom(null)}>time {fmtT(zoom[0])}–{fmtT(zoom[1])}<Icon name="x" size={12} /></button>}
          {[...tokens].map(t => <button key={t} type="button" className="lg-chip" onClick={() => toggleToken(t)} title={t}>{t.length > 40 ? `${t.slice(0, 38)}…` : t}<Icon name="x" size={12} /></button>)}
          {needle && <button type="button" className="lg-chip" onClick={() => setExclude('')}>− {exclude}<Icon name="x" size={12} /></button>}
          {[...levels].map(l => <button key={l} type="button" className="lg-chip" onClick={() => toggleLevel(l)}>{l}<Icon name="x" size={12} /></button>)}
          <button type="button" className="lg-clear" onClick={clearAll}>Clear all</button>
        </div>)}

      <Histogram rows={rows} zoom={zoom} onZoom={setZoom} />
      {error && <div className="lg-error" role="alert"><Icon name="alert" size={15} /><span>{error}</span><button className="btn sm" onClick={() => void doFetch()}>Retry</button></div>}

      <div className={`lg-body ${prefs.dense ? 'dense' : ''} ${prefs.wrap ? 'wrap' : ''}`}>
        {text === null ? (
          <div className="lg-skel">{Array.from({ length: 12 }, (_, i) => <i key={i} style={{ width: `${30 + ((i * 53) % 62)}%` }} />)}</div>
        ) : entries.length === 0 ? (
          <div className="lg-empty"><Icon name="logs" size={28} /><h3>{rows.length ? 'No lines match your filters' : applied ? `Nothing contains “${applied}”` : `No log lines in the ${range.long.toLowerCase()}`}</h3>
            <p>{rows.length ? <>Clear the filters to see all {rows.length.toLocaleString()} lines. <button type="button" className="lg-link" onClick={() => { clearAll(); setSearch(''); setApplied(''); }}>Reset filters</button></> : applied ? 'Try a different search term or a wider time range.' : <>This log has been quiet. {range.id !== '1mo' && <button type="button" className="lg-link" onClick={() => setPref('range', nextRange.id)}>Look back further ({nextRange.long.toLowerCase()})</button>}</>}</p>
            {emptyHint}</div>
        ) : (
          <div className="lg-scroll" ref={scroller} onScroll={onScroll}>
            <div className="lg-head" aria-hidden="true"><span>#</span><span>Time</span><span>Level</span><span>Message</span></div>
            {entries.map(en => {
              const r = en.row, many = en.items.length > 1, open = many && !folded.has(en.key);   // groups start collapsed: `folded` holds the ones the user opened
              const isNew = fresh.has(`${r.t ?? ''}|${r.raw}`);
              const last = en.items[en.items.length - 1];
              return (
                <Fragment key={en.key}>
                  <div className={`lg-item ${r.level} ${selected === r.n ? 'sel' : ''} ${isNew ? 'new' : ''}`}>
                    <div className="lg-row" onClick={() => setSelected(r.n)} role="button" tabIndex={0} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setSelected(r.n))}>
                      <span className="lg-n">{many ? `${r.n}–${last.n}` : r.n}</span>
                      <span className="lg-t" title={r.tsTitle}>{r.ts}</span>
                      <span className="lg-l">{r.level ? <em className={r.level}>{LEVEL_LABEL[r.level]}</em> : null}</span>
                      <span className="lg-m">{many && <button type="button" className="lg-group" onClick={e => { e.stopPropagation(); toggleFold(en.key); }} aria-expanded={!open}>{open ? '▾' : '▸'} {en.items.length}× similar{r.t != null && last.t != null && last.t !== r.t ? <small>{fmtT(r.t)}–{fmtT(last.t)}</small> : null}</button>}{message(r)}</span>
                    </div>
                  </div>
                  {open && en.items.map(sub => (
                    <div key={sub.n} className={`lg-item sub ${sub.level} ${selected === sub.n ? 'sel' : ''}`}>
                      <div className="lg-row" onClick={() => setSelected(sub.n)} role="button" tabIndex={0}>
                        <span className="lg-n">↳ {sub.n}</span><span className="lg-t" title={sub.tsTitle}>{sub.ts}</span><span className="lg-l" /><span className="lg-m">{message(sub)}</span></div>
                    </div>))}
                </Fragment>);
            })}
          </div>)}
        {!stuck && entries.length > 0 && <button className="lg-jump" onClick={() => { setStuck(true); const el = scroller.current; if (el) el.scrollTop = prefs.newest ? 0 : el.scrollHeight; }}>{prefs.newest ? '↑ Jump to newest' : '↓ Jump to newest'}{fresh.size ? ` · ${fresh.size} new` : ''}</button>}
      </div>

      <div className="lg-foot">
        <span><b>{filtered.length.toLocaleString()}</b>{filtered.length !== rows.length ? ` of ${rows.length.toLocaleString()}` : ''} lines</span>
        {truncated && <span className="warn">showing the newest part only</span>}
        {fetchedAt && <span className="muted">{live ? 'live · ' : ''}updated {fetchedAt.toLocaleTimeString([], { hour12: false })} · {took.toFixed(1)}s</span>}
        <span className="grow" />
        <button type="button" className="btn ghost sm" onClick={() => copy(filtered.map(r => r.raw).join('\n'))} disabled={!filtered.length}>Copy</button>
        <button type="button" className="btn ghost sm" onClick={download} disabled={!filtered.length}>Download</button>
      </div>
      {selRow && <LogInspector row={selRow} index={selIndex} total={flat.length} onClose={() => setSelected(null)} onNav={d => { const n = flat[selIndex + d]; if (n) setSelected(n.n); }} onToken={toggleToken} tokens={tokens} onZoom={setZoom} />}
    </div>
  );
}
