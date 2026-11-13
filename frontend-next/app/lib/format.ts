export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

export function bytesPerSecond(value: number | null | undefined): string {
  if (value == null) return '–';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let n = value, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)} ${units[i]}`;
}

export const pct = (value: number | null | undefined, digits = 1) => (value == null ? '–' : `${value.toFixed(digits)}%`);
export const ms = (value: number | null | undefined) => (value == null ? '–' : `${Math.round(value)} ms`);
export const clock = (iso: string, withDate = false) => {
  const d = new Date(iso);
  return withDate ? d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};
export const uptimeClass = (value: number | null | undefined) => (value == null ? 'none' : value >= 99.9 ? 'good' : value >= 99 ? 'warn' : 'bad');

/** True when `current` is an older release than `latest` (numeric compare: 2.10.0 > 2.9.9). */
export function isOlder(current: string | null | undefined, latest: string | null | undefined): boolean {
  const parse = (v?: string | null) => (v ?? '').match(/\d+/g)?.slice(0, 4).map(Number) ?? [];
  const a = parse(current), b = parse(latest);
  if (!a.length || !b.length) return false;
  for (let i = 0; i < Math.max(a.length, b.length); i++) { if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0); }
  return false;
}
