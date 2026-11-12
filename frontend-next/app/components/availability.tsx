'use client';

import { useState } from 'react';
import { api } from '../lib/api';
import { usePoll } from '../lib/app';
import { pct, uptimeClass } from '../lib/format';

type Bucket = { t: string; pct: number | null; checks: number; down: number };
type Availability = { range: string; bucket_seconds: number; buckets: Bucket[]; checks: number; uptime_pct: number | null };

export const RANGES: { id: string; label: string; title: string }[] = [
  { id: '1m', label: '1m', title: 'Last minute' }, { id: '5m', label: '5m', title: 'Last 5 minutes' }, { id: '15m', label: '15m', title: 'Last 15 minutes' },
  { id: '30m', label: '30m', title: 'Last 30 minutes' }, { id: '1h', label: '1h', title: 'Last hour' }, { id: '4h', label: '4h', title: 'Last 4 hours' },
  { id: '12h', label: '12h', title: 'Last 12 hours' }, { id: '1d', label: '1d', title: 'Last day' }, { id: '1mo', label: '1 mo', title: 'Last month' },
  { id: '3mo', label: '3 mo', title: 'Last 3 months' }, { id: '1y', label: '1 yr', title: 'Last year' },
];

function describe(bucket: Bucket, seconds: number): string {
  const d = new Date(bucket.t);
  const when = seconds >= 7 * 86400 ? `Week of ${d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}`
    : seconds >= 86400 ? d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })
    : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: seconds < 60 ? '2-digit' : undefined });
  if (bucket.pct == null) return `${when} · no checks`;
  return `${when} · ${bucket.pct.toFixed(bucket.pct === 100 || bucket.pct === 0 ? 0 : 2)}% available · ${bucket.checks} check${bucket.checks === 1 ? '' : 's'}${bucket.down ? `, ${bucket.down} failed` : ''}`;
}

/** Status bar with a selectable window from 1 minute to 1 year. Each cell is one equal slice of that window. */
export function AvailabilityPanel({ kind, id }: { kind: 'servers' | 'services'; id: number }) {
  const [range, setRange] = useState('1d');
  const [hover, setHover] = useState<Bucket | null>(null);
  const { value, error } = usePoll(() => api<Availability>(`/${kind}/${id}/availability?range=${range}`), [kind, id, range], range === '1m' || range === '5m' ? 5000 : 15000);
  const current = RANGES.find(r => r.id === range)!;
  const first = value?.buckets[0], last = value?.buckets[value.buckets.length - 1];
  const edge = (b?: Bucket) => (b ? new Date(b.t).toLocaleString([], value!.bucket_seconds >= 86400 ? { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' } : { hour: '2-digit', minute: '2-digit' }) : '');

  return (
    <section className="card">
      <div className="card-head">
        <h2>Availability · {current.title.toLowerCase()}</h2><span className="grow" />
        {value && <span className={`sm ${uptimeClass(value.uptime_pct)}`}>{pct(value.uptime_pct, 2)} <span className="muted">· {value.checks} checks</span></span>}
      </div>
      <div className="seg" style={{ flexWrap: 'wrap', marginBottom: 14 }} role="tablist" aria-label="Time range">
        {RANGES.map(r => <button key={r.id} role="tab" aria-selected={range === r.id} className={range === r.id ? 'on' : ''} title={r.title} onClick={() => setRange(r.id)}>{r.label}</button>)}
      </div>
      {error ? <p className="err">{error}</p> : !value ? <p className="muted sm">Loading…</p> : (
        <>
          <div className="uptime-bar" role="img" aria-label={`Availability, ${current.title}`} onMouseLeave={() => setHover(null)}>
            {value.buckets.map(b => <i key={b.t} className={uptimeClass(b.pct)} onMouseEnter={() => setHover(b)} />)}
          </div>
          <div className="scale"><span>{edge(first)}</span><span>{hover ? <b style={{ color: 'var(--ink)' }}>{describe(hover, value.bucket_seconds)}</b> : `each bar = ${fmtSpan(value.bucket_seconds)}`}</span><span>{range.endsWith('m') || range.endsWith('h') || range === '1d' ? 'now' : 'Today'}</span></div>
        </>
      )}
    </section>
  );
}

function fmtSpan(s: number) {
  if (s >= 7 * 86400) return '1 week';
  if (s >= 86400) return '1 day';
  if (s >= 3600) return `${s / 3600} hour${s > 3600 ? 's' : ''}`;
  if (s >= 60) return `${s / 60} min`;
  return `${s} sec`;
}
