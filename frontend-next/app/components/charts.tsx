'use client';

import { useEffect, useId, useRef, useState } from 'react';
import type { Daily, Point } from '../lib/types';
import { clock, uptimeClass } from '../lib/format';

export type Series = { key: string; label: string; color: string; format?: (v: number) => string; peakKey?: string };
export type RefLine = { value: number; label: string; color?: string };

/** Responsive multi-series area/line chart with hover tooltip. Pure SVG, no dependencies.
 *  Built to tell the truth: gaps in the data are shown as gaps (a stopped agent is not a straight line), `peakKey` draws the highest
 *  value in each bucket next to the average (averages hide spikes), `refLines` mark limits, and `percent` scales a 0-100 % chart to
 *  what the data actually does instead of squashing it into the bottom of a fixed 0-100 axis. */
export function AreaChart({ points, series, height = 180, yMax, percent = false, unit = '', stacked = false, showDate = false, axisFormat, refLines = [] }: {
  points: Point[]; series: Series[]; height?: number; yMax?: number; percent?: boolean; unit?: string; stacked?: boolean; showDate?: boolean; axisFormat?: (v: number) => string; refLines?: RefLine[];
}) {
  const ref = useRef<HTMLDivElement>(null);
  const uid = useId().replace(/:/g, '');
  const [hover, setHover] = useState<number | null>(null);
  const [W, setW] = useState(600);   // the drawing is as wide as its box, so 1 unit is 1 pixel and the text stays readable in narrow cards
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => setW(Math.max(220, Math.round(el.getBoundingClientRect().width)));
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, [points.length === 0]);
  const padL = 40, padB = 18, padT = 8, H = height;
  if (points.length === 0) return <div ref={ref} className="muted sm" style={{ height, display: 'grid', placeItems: 'center' }}>No data in this range yet</div>;

  const times = points.map(p => new Date(p.t).getTime());
  const t0 = times[0], t1 = times[times.length - 1] > t0 ? times[times.length - 1] : t0 + 1;
  const num = (p: Point, key?: string) => (key && p[key] != null ? Number(p[key]) : null);
  const peakOf = Math.max(0, ...points.flatMap(p => series.flatMap(s => [num(p, s.key), num(p, s.peakKey)].filter((v): v is number => v != null))));
  const top = yMax ?? (percent ? percentTop(peakOf) : niceMax(Math.max(1, peakOf)));
  const x = (t: number) => padL + ((t - t0) / Math.max(1, t1 - t0)) * (W - padL - 4);
  const y = (v: number) => padT + (1 - Math.min(v, top) / top) * (H - padT - padB);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => f * top);

  // A gap is a stretch much longer than the normal spacing between points (agent offline, no checks): never draw a line across it.
  const diffs = times.slice(1).map((t, i) => t - times[i]).filter(d => d > 0).sort((p, q) => p - q);
  const typical = diffs.length ? diffs[Math.floor(diffs.length / 2)] : 0;
  const gapMs = Math.max(typical * 3, 120_000);
  const segments: number[][] = [];
  points.forEach((_, i) => { if (i === 0 || times[i] - times[i - 1] > gapMs) segments.push([i]); else segments[segments.length - 1].push(i); });
  const gaps = segments.slice(1).map((seg, k) => ({ from: times[segments[k][segments[k].length - 1]], to: times[seg[0]] }));

  const line = (key: string) => segments.map(seg => {
    const pts = seg.filter(i => points[i][key] != null);
    if (pts.length === 1) { const i = pts[0]; return `M${(x(times[i]) - 0.01).toFixed(1)},${y(Number(points[i][key])).toFixed(1)} L${(x(times[i]) + 0.01).toFixed(1)},${y(Number(points[i][key])).toFixed(1)}`; }
    return pts.map((i, n) => `${n === 0 ? 'M' : 'L'}${x(times[i]).toFixed(1)},${y(Number(points[i][key])).toFixed(1)}`).join(' ');
  }).filter(Boolean).join(' ');
  const area = (key: string) => segments.map(seg => {
    const pts = seg.filter(i => points[i][key] != null);
    if (pts.length < 2) return '';
    return `${pts.map((i, n) => `${n === 0 ? 'M' : 'L'}${x(times[i]).toFixed(1)},${y(Number(points[i][key])).toFixed(1)}`).join(' ')} L${x(times[pts[pts.length - 1]]).toFixed(1)},${y(0)} L${x(times[pts[0]]).toFixed(1)},${y(0)} Z`;
  }).filter(Boolean).join(' ');

  // The band between the average and the highest value of each bucket: how far the spikes went.
  const band = (avgKey: string, peakKey: string) => segments.map(seg => {
    const pts = seg.filter(i => points[i][avgKey] != null && points[i][peakKey] != null);
    if (pts.length < 2) return '';
    const upper = pts.map(i => `${x(times[i]).toFixed(1)},${y(Math.max(Number(points[i][peakKey]), Number(points[i][avgKey]))).toFixed(1)}`);
    const lower = [...pts].reverse().map(i => `${x(times[i]).toFixed(1)},${y(Number(points[i][avgKey])).toFixed(1)}`);
    return `M${upper.join(' L')} L${lower.join(' L')} Z`;
  }).filter(Boolean).join(' ');

  const onMove = (event: React.MouseEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const t = t0 + ((event.clientX - rect.left) / rect.width * W - padL) / (W - padL - 4) * (t1 - t0);
    let best = 0;
    times.forEach((time, i) => { if (Math.abs(time - t) < Math.abs(times[best] - t)) best = i; });
    setHover(best);
  };
  const hp = hover != null ? points[hover] : null;
  const hx = hover != null ? x(times[hover]) / W : 0;
  const xCount = W < 380 ? 3 : W < 560 ? 4 : 5;   // fewer time labels in a narrow chart, so they never run into each other
  const xTicks = Array.from({ length: xCount }, (_, i) => t0 + (i / (xCount - 1)) * (t1 - t0));
  const fmtY = (v: number) => (axisFormat ? axisFormat(v) : <>{fmtAxis(v)}{unit}</>);

  return (
    <div className="chart" ref={ref} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={series.map(s => s.label).join(', ') + ' over time'}>
        <defs>
          {series.map(s => (
            <linearGradient key={s.key} id={`g-${uid}-${s.key}`} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={stacked ? 0.35 : 0.3} /><stop offset="100%" stopColor={s.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {ticks.map(v => (
          <g key={v}><line className="grid-line" x1={padL} x2={W - 4} y1={y(v)} y2={y(v)} /><text className="axis" x={padL - 6} y={y(v) + 3} textAnchor="end">{fmtY(v)}</text></g>
        ))}
        {xTicks.map((t, i) => <text key={i} className="axis" x={x(t)} y={H - 3} textAnchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}>{clock(new Date(t).toISOString(), showDate)}</text>)}
        {gaps.map((g, i) => <rect key={i} className="gap" x={x(g.from)} y={padT} width={Math.max(1, x(g.to) - x(g.from))} height={H - padT - padB}><title>No data (agent or monitor was not reporting)</title></rect>)}
        {refLines.filter(r => r.value <= top).map(r => (
          <g key={r.label}><line x1={padL} x2={W - 4} y1={y(r.value)} y2={y(r.value)} stroke={r.color ?? 'var(--bad)'} strokeWidth="1" strokeDasharray="5 4" opacity="0.8" />
            <text className="axis" x={W - 6} y={y(r.value) - 3} textAnchor="end" fill={r.color ?? 'var(--bad)'}>{r.label}</text></g>
        ))}
        {series.map(s => <path key={`a${s.key}`} d={area(s.key)} fill={`url(#g-${uid}-${s.key})`} />)}
        {series.filter(s => s.peakKey).map(s => <path key={`p${s.key}`} d={band(s.key, s.peakKey!)} fill={s.color} opacity="0.2"><title>Highest value in each interval</title></path>)}
        {series.map(s => <path key={`l${s.key}`} d={line(s.key)} fill="none" stroke={s.color} strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />)}
        {hover != null && <line className="cursor" x1={x(times[hover])} x2={x(times[hover])} y1={padT} y2={H - padB} />}
        {hover != null && hp && series.map(s => hp[s.key] != null && <circle key={s.key} cx={x(times[hover])} cy={y(Number(hp[s.key]))} r="3.5" fill={s.color} stroke="var(--surface)" strokeWidth="1.5" />)}
      </svg>
      {hp && (
        <div className="tip" style={{ left: `${Math.min(88, Math.max(12, hx * 100))}%`, top: 0 }}>
          <b>{clock(hp.t, true)}</b>
          {series.map(s => hp[s.key] != null && <span key={s.key}><i style={{ background: s.color }} />{s.label}: {(s.format ?? (v => `${v}${unit}`))(Number(hp[s.key]))}{s.peakKey && hp[s.peakKey] != null && Number(hp[s.peakKey]) > Number(hp[s.key]) ? <em className="muted"> · peak {(s.format ?? (v => `${v}${unit}`))(Number(hp[s.peakKey]))}</em> : null}</span>)}
        </div>
      )}
    </div>
  );
}

/** Top of a 0-100 % axis: the smallest "round" ceiling above the data (with a little headroom), never below 10 %. */
function percentTop(peak: number) {
  const want = Math.max(10, peak * 1.15);
  return [10, 20, 25, 40, 50, 75, 100].find(v => v >= want) ?? 100;
}

function niceMax(v: number) {
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / pow;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * pow;
}
const fmtAxis = (v: number) => (v >= 1e6 ? `${+(v / 1e6).toFixed(1)}M` : v >= 1e3 ? `${+(v / 1e3).toFixed(1)}k` : `${+v.toFixed(1)}`);

export function Sparkline({ values, color = 'var(--accent)', height = 34 }: { values: number[]; color?: string; height?: number }) {
  if (values.length < 2) return <div style={{ height }} />;
  const W = 120, max = Math.max(...values, 1), min = Math.min(...values, 0);
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * W},${height - 2 - ((v - min) / Math.max(1, max - min)) * (height - 4)}`);
  return (
    <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height} preserveAspectRatio="none" aria-hidden="true">
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** 90-day availability strip, one cell per day. */
export function UptimeBar({ days }: { days: Daily[] }) {
  return (
    <div>
      <div className="uptime-bar" role="img" aria-label={`Daily availability over the last ${days.length} days`}>
        {days.map(d => <i key={d.date} className={uptimeClass(d.pct)} title={`${d.date}: ${d.pct == null ? 'no data' : d.pct.toFixed(2) + '%'}`} />)}
      </div>
      <div className="scale"><span>{days.length} days ago</span><span>Today</span></div>
    </div>
  );
}

/** Circular gauge; colour flips at the configured alert threshold. */
export function Ring({ value, threshold, size = 74, label, display }: { value: number | undefined; threshold: number; size?: number; label: string; display?: string }) {
  const v = value ?? 0, r = size / 2 - 7, c = 2 * Math.PI * r;
  const color = value == null ? 'var(--none)' : v >= threshold ? 'var(--bad)' : v >= threshold * 0.85 ? 'var(--warn)' : 'var(--good)';
  return (
    <div>
      <div className="ring" style={{ width: size, height: size, margin: '0 auto' }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bg)" strokeWidth="7" />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="7" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - Math.min(100, v) / 100)} transform={`rotate(-90 ${size / 2} ${size / 2})`} style={{ transition: 'stroke-dashoffset .5s' }} />
        </svg>
        <b>{display ?? (value == null ? '–' : Math.round(v))}</b>
      </div>
      <div className="lbl">{label}</div>
    </div>
  );
}
