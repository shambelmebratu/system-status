'use client';

import { useRef, useState } from 'react';
import type { Daily, Point } from '../lib/types';
import { clock, uptimeClass } from '../lib/format';

export type Series = { key: string; label: string; color: string; format?: (v: number) => string };

/** Responsive multi-series area/line chart with hover tooltip. Pure SVG, no dependencies. */
export function AreaChart({ points, series, height = 180, yMax, unit = '', stacked = false, showDate = false }: {
  points: Point[]; series: Series[]; height?: number; yMax?: number; unit?: string; stacked?: boolean; showDate?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const W = 600, padL = 34, padB = 18, padT = 6, H = height;
  if (points.length === 0) return <div className="muted sm" style={{ height, display: 'grid', placeItems: 'center' }}>No data in this range yet</div>;

  const times = points.map(p => new Date(p.t).getTime());
  const t0 = times[0], t1 = times[times.length - 1] || t0 + 1;
  const values = points.flatMap(p => series.map(s => Number(p[s.key] ?? 0)));
  const top = yMax ?? niceMax(Math.max(1, ...values));
  const x = (t: number) => padL + ((t - t0) / Math.max(1, t1 - t0)) * (W - padL - 4);
  const y = (v: number) => padT + (1 - v / top) * (H - padT - padB);
  const ticks = [0, 0.5, 1].map(f => f * top);

  const path = (key: string) => points.map((p, i) => (p[key] == null ? null : `${i === 0 ? 'M' : 'L'}${x(times[i]).toFixed(1)},${y(Number(p[key])).toFixed(1)}`)).filter(Boolean).join(' ');
  const area = (key: string) => {
    const valid = points.map((p, i) => ({ i, v: p[key] })).filter(item => item.v != null);
    if (valid.length < 2) return '';
    const first = x(times[valid[0].i]), last = x(times[valid[valid.length - 1].i]);
    return `${path(key)} L${last.toFixed(1)},${y(0)} L${first.toFixed(1)},${y(0)} Z`;
  };

  const onMove = (event: React.MouseEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const t = t0 + ((event.clientX - rect.left) / rect.width * W - padL) / (W - padL - 4) * (t1 - t0);
    let best = 0;
    times.forEach((time, i) => { if (Math.abs(time - t) < Math.abs(times[best] - t)) best = i; });
    setHover(best);
  };
  const hp = hover != null ? points[hover] : null;
  const hx = hover != null ? x(times[hover]) / W : 0;

  return (
    <div className="chart" ref={ref} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={series.map(s => s.label).join(', ') + ' over time'}>
        <defs>
          {series.map(s => (
            <linearGradient key={s.key} id={`g-${s.key}`} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={stacked ? 0.35 : 0.3} /><stop offset="100%" stopColor={s.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {ticks.map(v => (
          <g key={v}><line className="grid-line" x1={padL} x2={W - 4} y1={y(v)} y2={y(v)} /><text className="axis" x={padL - 6} y={y(v) + 3} textAnchor="end">{fmtAxis(v)}{unit}</text></g>
        ))}
        <text className="axis" x={padL} y={H - 3}>{clock(points[0].t, showDate)}</text>
        <text className="axis" x={W - 4} y={H - 3} textAnchor="end">{clock(points[points.length - 1].t, showDate)}</text>
        {series.map(s => <path key={`a${s.key}`} d={area(s.key)} fill={`url(#g-${s.key})`} />)}
        {series.map(s => <path key={`l${s.key}`} d={path(s.key)} fill="none" stroke={s.color} strokeWidth="1.8" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />)}
        {hover != null && <line className="cursor" x1={x(times[hover])} x2={x(times[hover])} y1={padT} y2={H - padB} />}
        {hover != null && hp && series.map(s => hp[s.key] != null && <circle key={s.key} cx={x(times[hover])} cy={y(Number(hp[s.key]))} r="3.5" fill={s.color} stroke="var(--surface)" strokeWidth="1.5" />)}
      </svg>
      {hp && (
        <div className="tip" style={{ left: `${Math.min(88, Math.max(12, hx * 100))}%`, top: 0 }}>
          <b>{clock(hp.t, true)}</b>
          {series.map(s => hp[s.key] != null && <span key={s.key}><i style={{ background: s.color }} />{s.label}: {(s.format ?? (v => `${v}${unit}`))(Number(hp[s.key]))}</span>)}
        </div>
      )}
    </div>
  );
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
      <div className="uptime-bar" role="img" aria-label="Daily availability over the last 90 days">
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
