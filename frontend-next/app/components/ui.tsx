'use client';

import { ReactNode, useEffect, useState } from 'react';
import type { Status } from '../lib/types';

const ICONS: Record<string, string> = {
  terminal: 'M3 5h18v14H3V5zm4 4l3 3-3 3m5 0h5',
  database: 'M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  overview: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
  server: 'M4 4h16v6H4V4zm0 10h16v6H4v-6zM7 7h.01M7 17h.01',
  globe: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 0c3 3 4 6.5 4 10s-1 7-4 10c-3-3-4-6.5-4-10s1-7 4-10zM2 12h20',
  alert: 'M12 3l10 18H2L12 3zm0 7v5m0 3h.01',
  bell: 'M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9zM13.7 21a2 2 0 01-3.4 0',
  settings: 'M12 15a3 3 0 100-6 3 3 0 000 6zm7.4-3a7.4 7.4 0 00-.1-1.3l2-1.6-2-3.4-2.4 1a7.6 7.6 0 00-2.2-1.3L14.3 3H9.7l-.4 2.4a7.6 7.6 0 00-2.2 1.3l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 000 2.6l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 002.2 1.3l.4 2.4h4.6l.4-2.4a7.6 7.6 0 002.2-1.3l2.4 1 2-3.4-2-1.6c.1-.4.1-.9.1-1.3z',
  plus: 'M12 5v14M5 12h14',
  pause: 'M8 5v14M16 5v14',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
  'chevron-down': 'M6 9l6 6 6-6',
  'chevron-right': 'M9 6l6 6-6 6',
  info: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 9v6m0-10h.01',
  package: 'M21 8l-9-5-9 5 9 5 9-5zM3 8v8l9 5 9-5V8M12 13v8',
  sliders: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  'shield-alert': 'M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3zm0 5v5m0 3h.01',
  search: 'M11 4a7 7 0 100 14 7 7 0 000-14zm10 17l-4.3-4.3',
  lock: 'M6 11h12v10H6zM8 11V7a4 4 0 018 0v4',
  play: 'M7 4l13 8-13 8V4z',
  eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12zm10-3a3 3 0 100 6 3 3 0 000-6z',
  check: 'M5 12l5 5 9-10',
  x: 'M6 6l12 12M18 6L6 18',
  refresh: 'M21 12a9 9 0 11-3-6.7L21 8m0-5v5h-5',
  menu: 'M4 6h16M4 12h16M4 18h16',
  sun: 'M12 17a5 5 0 100-10 5 5 0 000 10zM12 1v2m0 18v2M4.2 4.2l1.4 1.4m12.8 12.8l1.4 1.4M1 12h2m18 0h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z',
  back: 'M15 18l-6-6 6-6',
  logout: 'M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4m7 14l5-5-5-5m5 5H9',
  users: 'M17 21v-2a4 4 0 00-4-4H7a4 4 0 00-4 4v2M10 11a4 4 0 100-8 4 4 0 000 8zm11 10v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8',
  shield: 'M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3zm-3 9l2 2 4-4',
  logs: 'M4 5h16M4 10h16M4 15h10M4 20h7',
  clock: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 5v5l3 2',
  star: 'M12 2l3 7 7 .6-5.3 4.7 1.6 7.2L12 17.8 5.7 21.5l1.6-7.2L2 9.6 9 9l3-7z',
  k8s: 'M12 2l9 5v10l-9 5-9-5V7l9-5zm0 6a4 4 0 100 8 4 4 0 000-8zm0-6v6m0 8v6M3 7l6 3m6 4l6 3M21 7l-6 3m-6 4l-6 3',
  zap: 'M13 2L4 14h7l-1 8 9-12h-7l1-8z',
  external: 'M14 4h6v6m0-6L10 14M20 14v6H4V4h6',
};

export function Icon({ name, size = 18 }: { name: keyof typeof ICONS | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICONS[name] || ''} />
    </svg>
  );
}

const STATUS_LABEL: Record<string, string> = { up: 'Operational', down: 'Down', alert: 'Alert', unknown: 'Pending' };
export function StatusPill({ status, label }: { status: Status | string; label?: string }) {
  const key = ['up', 'down', 'alert'].includes(status) ? status : 'unknown';
  return <span className={`pill ${key}`}><i />{label ?? STATUS_LABEL[key]}</span>;
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty"><h3>{title}</h3>{children && <p>{children}</p>}{action}</div>;
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={event => event.target === event.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} style={wide ? { maxWidth: 860 } : undefined}>
        <div className="modal-head"><h2>{title}</h2><button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button></div>
        {children}
      </div>
    </div>
  );
}

export function CodeBox({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="codebox">
      {value}
      <button className="btn sm" type="button" onClick={() => { void navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return <label className="field">{label}{children}{hint && <small>{hint}</small>}</label>;
}

export function Meter({ value, warnAt, badAt }: { value: number; warnAt: number; badAt: number }) {
  const cls = value >= badAt ? 'bad' : value >= warnAt ? 'warn' : '';
  return <div className={`bar ${cls}`}><i style={{ width: `${Math.min(100, Math.max(0, value))}%` }} /></div>;
}


/** "Alert after N failed checks in a row" for a server or service: empty = the default; shows how long that is at this interval. */
export function ConfirmChecksField({ value, onChange, interval, fallback }: { value: string; onChange: (v: string) => void; interval: number; fallback: number }) {
  const n = Number(value) || fallback;
  const wait = n <= 1 ? 'alerts at the first failed check' : `about ${(() => { const s = (n - 1) * Math.max(1, interval); return s < 90 ? `${s} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`; })()} after the first failure (${n} × ${interval} s checks)`;
  return (
    <Field label="Alert after failed checks in a row" hint={`${value ? '' : `Empty = default (${fallback}). `}1 = alert immediately. With ${n}: ${wait}. Recovery is reported at once.`}>
      <input type="number" min={1} max={50} value={value} onChange={e => onChange(e.target.value)} placeholder={String(fallback)} />
    </Field>
  );
}

/** "confirming 1 of 3": a problem seen but not alerted yet. */
export function ConfirmingBadge({ failCount, needed, status }: { failCount?: number | null; needed?: number | null; status?: string }) {
  if (!failCount || !needed || needed <= 1 || status === 'down' || status === 'alert' || failCount >= needed) return null;
  return <span className="tag warn-tag" title="A failed check was seen; the alert is sent only if it fails again">confirming {failCount} of {needed}</span>;
}
